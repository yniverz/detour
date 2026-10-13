// Package proxy implements detour's HTTP handler: it authenticates the request,
// reads the upstream target(s) from trusted headers and reverse-proxies to them.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yniverz/detour/internal/balancer"
	"github.com/yniverz/detour/internal/config"
	"github.com/yniverz/detour/internal/guard"
	"github.com/yniverz/detour/internal/metrics"
	"github.com/yniverz/detour/internal/target"
)

// Server is the detour HTTP handler.
type Server struct {
	cfg            *config.Config
	keys           *guard.Keys
	sources        guard.PrefixSet
	targets        *guard.TargetPolicy
	health         *balancer.Health
	bal            *balancer.Balancer
	Metrics        *metrics.Metrics
	log            *slog.Logger
	secure         http.RoundTripper
	insecure       http.RoundTripper
	rp             *httputil.ReverseProxy
	defaultTargets []target.Target
	failStatus     map[int]bool
	parseOpts      target.ParseOptions
	now            func() time.Time
}

// New builds a Server from a validated configuration.
func New(cfg *config.Config, log *slog.Logger) (*Server, error) {
	sources, err := guard.ParsePrefixes(cfg.TrustedSources)
	if err != nil {
		return nil, fmt.Errorf("DETOUR_TRUSTED_SOURCES: %w", err)
	}
	tp, err := guard.ParseTargetPolicy(cfg.AllowedTargets, cfg.AllowAnyTarget)
	if err != nil {
		return nil, fmt.Errorf("DETOUR_ALLOWED_TARGETS: %w", err)
	}
	s := &Server{
		cfg:        cfg,
		keys:       guard.NewKeys(cfg.Keys),
		sources:    sources,
		targets:    tp,
		health:     balancer.NewHealth(cfg.MaxFails, cfg.FailTimeout),
		Metrics:    &metrics.Metrics{},
		log:        log,
		failStatus: map[int]bool{},
		parseOpts:  target.ParseOptions{AllowedSchemes: cfg.AllowedSchemes, MaxTargets: cfg.MaxTargets},
		now:        time.Now,
	}
	s.bal = balancer.New(s.health, cfg.MaxPools)
	for _, c := range cfg.FailStatus {
		s.failStatus[c] = true
	}

	var roots *x509.CertPool
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("DETOUR_CA_FILE: %w", err)
		}
		roots, err = x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("DETOUR_CA_FILE: no certificates found")
		}
	}
	s.secure = s.newTransport(&tls.Config{RootCAs: roots, InsecureSkipVerify: cfg.InsecureTLS}) //nolint:gosec // opt-in via config
	s.insecure = s.newTransport(&tls.Config{InsecureSkipVerify: true})                          //nolint:gosec // opt-in per request, gated by config

	if cfg.DefaultTarget != "" {
		ts, err := target.Parse(cfg.DefaultTarget, s.parseOpts)
		if err != nil {
			return nil, fmt.Errorf("DETOUR_DEFAULT_TARGET: %w", err)
		}
		for _, t := range ts {
			if err := tp.CheckHost(t.URL.Hostname()); err != nil {
				return nil, fmt.Errorf("DETOUR_DEFAULT_TARGET %s: %w", t.URL.Host, err)
			}
		}
		s.defaultTargets = ts
	}

	s.rp = &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		Transport:      &retryTransport{s: s},
		ModifyResponse: s.modifyResponse,
		ErrorHandler:   s.errorHandler,
		FlushInterval:  cfg.FlushInterval,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return s, nil
}

func (s *Server) newTransport(tc *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:                 nil, // never use HTTP(S)_PROXY for upstream connections
		DialContext:           s.targets.Dialer(s.cfg.DialTimeout, 30*time.Second, nil),
		TLSClientConfig:       tc,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          1024,
		MaxIdleConnsPerHost:   s.cfg.MaxIdlePerHst,
		IdleConnTimeout:       s.cfg.IdleConnTO,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: s.cfg.RespHdrTO,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// DownCount returns how many upstreams are currently marked down.
func (s *Server) DownCount() int { return len(s.health.Down(s.now())) }

// route is the per-request routing decision, carried in the request context.
type route struct {
	candidates       []target.Target
	attempts         int
	stripPrefix      string
	hostMode         config.HostMode
	hostLiteral      string
	insecure         bool
	rewriteRedirects bool
	rewriteCookies   bool
	inURL            *url.URL
	peerIP           string

	chosen   *target.Target
	tries    int
	upstream string
}

type ctxKey struct{}

func routeFrom(ctx context.Context) *route {
	r, _ := ctx.Value(ctxKey{}).(*route)
	return r
}

type rejectError struct {
	status int
	reason string
	msg    string
}

func (e *rejectError) Error() string { return e.msg }

func reject(status int, reason, format string, args ...any) *rejectError {
	return &rejectError{status: status, reason: reason, msg: fmt.Sprintf(format, args...)}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.now()
	s.Metrics.InFlight.Add(1)
	defer s.Metrics.InFlight.Add(-1)
	rec := &statusRecorder{ResponseWriter: w}

	rt, rej := s.decide(r)
	if rej != nil {
		s.Metrics.Rejected.Inc(rej.reason)
		http.Error(rec, http.StatusText(rej.status)+": "+rej.msg, rej.status)
		s.finish(r, rec, start, nil, rej.reason)
		return
	}
	s.rp.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), ctxKey{}, rt)))
	s.finish(r, rec, start, rt, "")
}

func (s *Server) finish(r *http.Request, rec *statusRecorder, start time.Time, rt *route, reason string) {
	status := rec.status
	if status == 0 {
		status = http.StatusOK
	}
	s.Metrics.Requests.Inc(metrics.StatusClass(status))
	if !s.cfg.AccessLog {
		return
	}
	attrs := []any{
		"method", r.Method, "host", r.Host, "path", r.URL.Path, "status", status,
		"bytes", rec.bytes, "duration_ms", s.now().Sub(start).Milliseconds(), "remote", r.RemoteAddr,
	}
	if rt != nil {
		attrs = append(attrs, "upstream", rt.upstream, "attempts", rt.tries)
	}
	if reason != "" {
		attrs = append(attrs, "rejected", reason)
	}
	s.log.Info("request", attrs...)
}

// decide performs all checks and builds the routing decision.
func (s *Server) decide(r *http.Request) (*route, *rejectError) {
	if r.Method == http.MethodConnect {
		return nil, reject(http.StatusMethodNotAllowed, "method", "CONNECT is not supported")
	}
	peer, ok := guard.RemoteIP(r.RemoteAddr)
	if len(s.sources) > 0 && (!ok || !s.sources.Contains(peer)) {
		return nil, reject(http.StatusForbidden, "source", "source not trusted")
	}
	if !s.cfg.AuthDisabled && !s.keys.Valid(r.Header.Get(s.cfg.HeaderKey())) {
		return nil, reject(http.StatusForbidden, "key", "missing or invalid key")
	}

	var ts []target.Target
	if v := strings.Join(r.Header.Values(s.cfg.HeaderTarget()), ","); strings.TrimSpace(v) != "" {
		parsed, err := target.Parse(v, s.parseOpts)
		if err != nil {
			return nil, reject(http.StatusBadRequest, "bad_target", "%v", err)
		}
		for _, t := range parsed {
			if err := s.targets.CheckHost(t.URL.Hostname()); err != nil {
				return nil, reject(http.StatusForbidden, "target_not_allowed", "target %s not allowed", t.URL.Host)
			}
		}
		ts = parsed
	} else if len(s.defaultTargets) > 0 {
		ts = s.defaultTargets
	} else {
		return nil, reject(http.StatusBadRequest, "no_target", "no %s header", s.cfg.HeaderTarget())
	}

	rt := &route{
		hostMode:         s.cfg.HostMode,
		rewriteRedirects: s.cfg.RewriteRedirects,
		rewriteCookies:   s.cfg.RewriteCookiePath,
		inURL:            r.URL,
	}
	if ok {
		rt.peerIP = peer.String()
	}
	policy := s.cfg.DefaultPolicy

	h := r.Header
	if s.cfg.AllowOverrides {
		if v := strings.TrimSpace(h.Get(s.cfg.HeaderPolicy())); v != "" {
			p, err := balancer.ParsePolicy(v)
			if err != nil {
				return nil, reject(http.StatusBadRequest, "bad_policy", "%v", err)
			}
			policy = p
		}
		if v := strings.TrimSpace(h.Get(s.cfg.HeaderHost())); v != "" {
			switch strings.ToLower(v) {
			case string(config.HostIncoming):
				rt.hostMode = config.HostIncoming
			case string(config.HostTarget):
				rt.hostMode = config.HostTarget
			default:
				if !validHost(v) {
					return nil, reject(http.StatusBadRequest, "bad_host", "invalid %s value", s.cfg.HeaderHost())
				}
				rt.hostLiteral = v
			}
		}
		if v := strings.TrimSpace(h.Get(s.cfg.HeaderStripPrefix())); v != "" {
			if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "?# ") {
				return nil, reject(http.StatusBadRequest, "bad_strip_prefix", "invalid %s value", s.cfg.HeaderStripPrefix())
			}
			rt.stripPrefix = v
		}
		if v := strings.TrimSpace(h.Get(s.cfg.HeaderRewriteRedirects())); v != "" {
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, reject(http.StatusBadRequest, "bad_rewrite", "invalid %s value", s.cfg.HeaderRewriteRedirects())
			}
			rt.rewriteRedirects, rt.rewriteCookies = b, b
		}
	}
	if v := strings.TrimSpace(h.Get(s.cfg.HeaderInsecure())); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, reject(http.StatusBadRequest, "bad_insecure", "invalid %s value", s.cfg.HeaderInsecure())
		}
		if b && !s.cfg.AllowInsecureTLS {
			return nil, reject(http.StatusForbidden, "insecure_not_allowed", "%s is disabled (DETOUR_ALLOW_INSECURE_TLS)", s.cfg.HeaderInsecure())
		}
		rt.insecure = b
	}

	rt.candidates = s.bal.Order(ts, policy, s.clientKey(r, rt.peerIP))
	rt.attempts = len(rt.candidates)
	if s.cfg.Retries >= 0 && s.cfg.Retries+1 < rt.attempts {
		rt.attempts = s.cfg.Retries + 1
	}
	return rt, nil
}

// clientKey returns the client identity used by the iphash policy.
func (s *Server) clientKey(r *http.Request, peer string) string {
	if s.cfg.ClientIPHeader != "" {
		vals := r.Header.Values(s.cfg.ClientIPHeader)
		if len(vals) > 0 {
			// Take the right-most entry: the one added by the closest trusted proxy.
			parts := strings.Split(vals[len(vals)-1], ",")
			if v := strings.TrimSpace(parts[len(parts)-1]); v != "" {
				if a, err := netip.ParseAddr(v); err == nil {
					return a.Unmap().String()
				}
			}
		}
	}
	return peer
}

func validHost(v string) bool {
	if len(v) > 255 {
		return false
	}
	for _, c := range v {
		if c <= ' ' || c == '/' || c == '?' || c == '#' || c == '@' || c == 0x7f {
			return false
		}
	}
	return true
}

// rewrite prepares the outbound request (URL is finalised per attempt by the transport).
func (s *Server) rewrite(pr *httputil.ProxyRequest) {
	rt := routeFrom(pr.In.Context())
	first := rt.candidates[0]
	pr.Out.URL = target.BuildURL(first.URL, rt.inURL, rt.stripPrefix)

	switch {
	case rt.hostLiteral != "":
		pr.Out.Host = rt.hostLiteral
	case rt.hostMode == config.HostTarget:
		pr.Out.Host = first.URL.Host
	default:
		pr.Out.Host = pr.In.Host
	}

	// Never forward detour's control headers (they include the key).
	for k := range pr.Out.Header {
		if strings.HasPrefix(k, s.cfg.HeaderPrefix) {
			pr.Out.Header.Del(k)
		}
	}

	in := pr.In.Header
	switch s.cfg.Forwarded {
	case config.ForwardedPreserve:
		copyHeader(pr.Out.Header, in, "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto")
	case config.ForwardedAppend:
		xff := strings.Join(in.Values("X-Forwarded-For"), ", ")
		if rt.peerIP != "" {
			if xff != "" {
				xff += ", "
			}
			xff += rt.peerIP
		}
		if xff != "" {
			pr.Out.Header.Set("X-Forwarded-For", xff)
		}
		if v := in.Get("X-Forwarded-Host"); v != "" {
			pr.Out.Header.Set("X-Forwarded-Host", v)
		} else {
			pr.Out.Header.Set("X-Forwarded-Host", pr.In.Host)
		}
		if v := in.Get("X-Forwarded-Proto"); v != "" {
			pr.Out.Header.Set("X-Forwarded-Proto", v)
		} else if pr.In.TLS != nil {
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		} else {
			pr.Out.Header.Set("X-Forwarded-Proto", "http")
		}
	case config.ForwardedNone:
		pr.Out.Header.Del("X-Forwarded-For")
		pr.Out.Header.Del("X-Forwarded-Host")
		pr.Out.Header.Del("X-Forwarded-Proto")
	}
}

func copyHeader(dst, src http.Header, names ...string) {
	for _, n := range names {
		if v := src.Values(n); len(v) > 0 {
			dst[http.CanonicalHeaderKey(n)] = append([]string(nil), v...)
		}
	}
}

// retryTransport tries the ordered candidates, marking failures for passive health.
type retryTransport struct{ s *Server }

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s := t.s
	rt := routeFrom(req.Context())
	tr := s.secure
	if rt.insecure {
		tr = s.insecure
	}
	replayable := req.Body == nil || req.Body == http.NoBody

	var lastErr error
	for i := 0; i < rt.attempts; i++ {
		cand := rt.candidates[i]
		out := req.Clone(req.Context())
		out.URL = target.BuildURL(cand.URL, rt.inURL, rt.stripPrefix)
		if rt.hostLiteral == "" && rt.hostMode == config.HostTarget {
			out.Host = cand.URL.Host
		}
		if i > 0 {
			out.Body = req.Body // nil/NoBody only (replayable)
			s.Metrics.Retries.Add(1)
		}
		rt.chosen, rt.tries, rt.upstream = &rt.candidates[i], i+1, cand.Origin()

		release := s.health.Acquire(cand.Origin())
		resp, err := tr.RoundTrip(out)
		if err != nil {
			release()
			if req.Context().Err() != nil {
				return nil, err // client went away; not the upstream's fault
			}
			lastErr = err
			s.Metrics.UpstreamErrors.Add(1)
			if errors.Is(err, guard.ErrTargetNotAllowed) {
				return nil, err
			}
			if s.health.Failure(cand.Origin(), s.now()) {
				s.Metrics.MarkedDown.Add(1)
				s.log.Warn("upstream marked down", "upstream", cand.Origin(), "for", s.cfg.FailTimeout.String(), "error", err.Error())
			} else {
				s.log.Debug("upstream attempt failed", "upstream", cand.Origin(), "error", err.Error())
			}
			if !replayable {
				return nil, err
			}
			continue
		}
		if s.failStatus[resp.StatusCode] {
			s.Metrics.UpstreamErrors.Add(1)
			if s.health.Failure(cand.Origin(), s.now()) {
				s.Metrics.MarkedDown.Add(1)
				s.log.Warn("upstream marked down", "upstream", cand.Origin(), "for", s.cfg.FailTimeout.String(), "status", resp.StatusCode)
			}
		} else {
			s.health.Success(cand.Origin())
		}
		resp.Body = wrapBody(resp.Body, release)
		return resp, nil
	}
	return nil, lastErr
}

// wrapBody releases the in-flight slot when the body is closed, preserving
// io.Writer for 101 Switching Protocols responses (WebSockets).
func wrapBody(b io.ReadCloser, release func()) io.ReadCloser {
	if b == nil {
		release()
		return b
	}
	if rwc, ok := b.(io.ReadWriteCloser); ok {
		return &releaseRWC{ReadWriteCloser: rwc, release: release}
	}
	return &releaseRC{ReadCloser: b, release: release}
}

type releaseRC struct {
	io.ReadCloser
	release func()
}

func (r *releaseRC) Close() error { defer r.release(); return r.ReadCloser.Close() }

type releaseRWC struct {
	io.ReadWriteCloser
	release func()
}

func (r *releaseRWC) Close() error { defer r.release(); return r.ReadWriteCloser.Close() }

func (s *Server) modifyResponse(resp *http.Response) error {
	rt := routeFrom(resp.Request.Context())
	if rt == nil || rt.chosen == nil {
		return nil
	}
	if rt.rewriteRedirects {
		if loc := resp.Header.Get("Location"); loc != "" {
			if nl, changed := rewriteLocation(loc, rt.chosen.URL, rt.stripPrefix); changed {
				resp.Header.Set("Location", nl)
			}
		}
		if v := resp.Header.Get("Content-Location"); v != "" {
			if nl, changed := rewriteLocation(v, rt.chosen.URL, rt.stripPrefix); changed {
				resp.Header.Set("Content-Location", nl)
			}
		}
	}
	if rt.rewriteCookies {
		if cs := resp.Header.Values("Set-Cookie"); len(cs) > 0 {
			out := make([]string, len(cs))
			for i, c := range cs {
				out[i] = rewriteCookiePath(c, rt.chosen.URL.Path, rt.stripPrefix)
			}
			resp.Header["Set-Cookie"] = out
		}
	}
	if s.cfg.ExposeUpstream {
		resp.Header.Set(s.cfg.HeaderUpstream(), rt.chosen.Origin())
	}
	return nil
}

func (s *Server) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		// Client disconnected; nginx logs this as 499.
		if rec, ok := w.(*statusRecorder); ok && rec.status == 0 {
			rec.status = 499
		}
		return
	}
	status := http.StatusBadGateway
	reason := "upstream_error"
	var ne net.Error
	switch {
	case errors.Is(err, guard.ErrTargetNotAllowed):
		status, reason = http.StatusForbidden, "target_not_allowed"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		status, reason = http.StatusGatewayTimeout, "upstream_timeout"
	}
	s.log.Warn("upstream request failed", "host", r.Host, "path", r.URL.Path, "status", status, "error", err.Error())
	s.Metrics.Rejected.Inc(reason)
	http.Error(w, http.StatusText(status), status)
}

// statusRecorder records the status code and byte count; it supports Flush and
// exposes the underlying writer via Unwrap (needed for WebSocket hijacking).
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 || r.status < 200 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += int64(n)
	return n, err
}

func (r *statusRecorder) Flush() { _ = http.NewResponseController(r.ResponseWriter).Flush() }

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
