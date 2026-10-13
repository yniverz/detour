package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yniverz/detour/internal/balancer"
	"github.com/yniverz/detour/internal/config"
)

const testKey = "s3cret"

func testConfig(mod func(*config.Config)) *config.Config {
	c := &config.Config{
		HeaderPrefix:      "X-Detour-",
		Keys:              []string{testKey},
		AllowedTargets:    []string{"127.0.0.0/8"},
		AllowedSchemes:    []string{"http", "https"},
		MaxTargets:        16,
		DefaultPolicy:     balancer.Failover,
		HostMode:          config.HostIncoming,
		RewriteRedirects:  true,
		RewriteCookiePath: true,
		Forwarded:         config.ForwardedAppend,
		AllowOverrides:    true,
		MaxFails:          1,
		FailTimeout:       time.Minute,
		Retries:           -1,
		DialTimeout:       2 * time.Second,
		IdleConnTO:        time.Second,
		MaxIdlePerHst:     4,
		LogLevel:          "info",
		LogFormat:         "text",
	}
	if mod != nil {
		mod(c)
	}
	return c
}

func newServer(t *testing.T, mod func(*config.Config)) *Server {
	t.Helper()
	s, err := New(testConfig(mod), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type seen struct {
	path, host string
	header     http.Header
}

func backend(t *testing.T, name string, rec *seen) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rec != nil {
			*rec = seen{path: r.URL.RequestURI(), host: r.Host, header: r.Header.Clone()}
		}
		_, _ = io.WriteString(w, name)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, h http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "192.0.2.10:5555"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAuthAndRouting(t *testing.T) {
	var got seen
	be := backend(t, "ok", &got)
	s := newServer(t, nil)

	if w := do(t, s, "GET", "http://study.example/page", map[string]string{"X-Detour-Target": be.URL}); w.Code != http.StatusForbidden {
		t.Fatalf("no key: %d", w.Code)
	}
	if w := do(t, s, "GET", "http://study.example/page", map[string]string{"X-Detour-Target": be.URL, "X-Detour-Key": "wrong"}); w.Code != http.StatusForbidden {
		t.Fatalf("wrong key: %d", w.Code)
	}
	if w := do(t, s, "GET", "http://study.example/page", map[string]string{"X-Detour-Key": testKey}); w.Code != http.StatusBadRequest {
		t.Fatalf("no target: %d", w.Code)
	}

	w := do(t, s, "GET", "http://study.example/page?x=1", map[string]string{
		"X-Detour-Target": be.URL + "/study",
		"X-Detour-Key":    testKey,
		"X-Detour-Custom": "must-not-leak",
		"X-Forwarded-For": "203.0.113.5",
	})
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("proxy: %d %q", w.Code, w.Body.String())
	}
	if got.path != "/study/page?x=1" {
		t.Errorf("upstream path = %s", got.path)
	}
	if got.host != "study.example" {
		t.Errorf("upstream host = %s (incoming host mode)", got.host)
	}
	for k := range got.header {
		if strings.HasPrefix(k, "X-Detour-") {
			t.Errorf("control header %s leaked upstream", k)
		}
	}
	if xff := got.header.Get("X-Forwarded-For"); xff != "203.0.113.5, 192.0.2.10" {
		t.Errorf("X-Forwarded-For = %q", xff)
	}
	if got.header.Get("X-Forwarded-Host") != "study.example" {
		t.Errorf("X-Forwarded-Host = %q", got.header.Get("X-Forwarded-Host"))
	}
}

func TestHostModeAndStripPrefix(t *testing.T) {
	var got seen
	be := backend(t, "ok", &got)
	s := newServer(t, nil)
	u, _ := url.Parse(be.URL)

	do(t, s, "GET", "http://pub.example/api/v1", map[string]string{
		"X-Detour-Target": be.URL + "/svc", "X-Detour-Key": testKey,
		"X-Detour-Host": "target", "X-Detour-Strip-Prefix": "/api",
	})
	if got.host != u.Host || got.path != "/svc/v1" {
		t.Errorf("host=%s path=%s", got.host, got.path)
	}
	do(t, s, "GET", "http://pub.example/", map[string]string{
		"X-Detour-Target": be.URL, "X-Detour-Key": testKey, "X-Detour-Host": "internal.name",
	})
	if got.host != "internal.name" {
		t.Errorf("literal host = %s", got.host)
	}
}

func TestTargetAllowlist(t *testing.T) {
	be := backend(t, "ok", nil)
	s := newServer(t, func(c *config.Config) { c.AllowedTargets = []string{"10.0.0.0/8"} })
	if w := do(t, s, "GET", "http://x/", map[string]string{"X-Detour-Target": be.URL, "X-Detour-Key": testKey}); w.Code != http.StatusForbidden {
		t.Fatalf("disallowed IP target: %d", w.Code)
	}
	port := be.URL[strings.LastIndex(be.URL, ":"):]
	// Hostname passes the request-time check but resolves to 127.0.0.1: blocked at dial time.
	if w := do(t, s, "GET", "http://x/", map[string]string{"X-Detour-Target": "http://localhost" + port, "X-Detour-Key": testKey}); w.Code != http.StatusForbidden {
		t.Fatalf("disallowed hostname target: %d %s", w.Code, w.Body.String())
	}
}

func TestTrustedSources(t *testing.T) {
	be := backend(t, "ok", nil)
	s := newServer(t, func(c *config.Config) { c.TrustedSources = []string{"10.20.30.0/24"} })
	if w := do(t, s, "GET", "http://x/", map[string]string{"X-Detour-Target": be.URL, "X-Detour-Key": testKey}); w.Code != http.StatusForbidden {
		t.Fatalf("untrusted source: %d", w.Code)
	}
}

func deadURL(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}

func TestFailoverRetryAndPassiveHealth(t *testing.T) {
	be := backend(t, "second", nil)
	dead := deadURL(t)
	s := newServer(t, nil)
	hdr := map[string]string{"X-Detour-Target": dead + "," + be.URL, "X-Detour-Key": testKey}

	w := do(t, s, "GET", "http://x/", hdr)
	if w.Code != http.StatusOK || w.Body.String() != "second" {
		t.Fatalf("failover: %d %q", w.Code, w.Body.String())
	}
	if s.Metrics.Retries.Load() != 1 || s.DownCount() != 1 {
		t.Fatalf("retries=%d down=%d", s.Metrics.Retries.Load(), s.DownCount())
	}
	// Dead upstream is now marked down: no further retry needed.
	do(t, s, "GET", "http://x/", hdr)
	if s.Metrics.Retries.Load() != 1 {
		t.Fatalf("down upstream was tried again")
	}
}

func TestNoRetryWithBody(t *testing.T) {
	be := backend(t, "second", nil)
	s := newServer(t, nil)
	req := httptest.NewRequest("POST", "http://x/", strings.NewReader("payload"))
	req.Header.Set("X-Detour-Target", deadURL(t)+","+be.URL)
	req.Header.Set("X-Detour-Key", testKey)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("POST with body should not be retried: %d", w.Code)
	}
}

func TestAllDownGives502(t *testing.T) {
	s := newServer(t, nil)
	w := do(t, s, "GET", "http://x/", map[string]string{"X-Detour-Target": deadURL(t), "X-Detour-Key": testKey})
	if w.Code != http.StatusBadGateway {
		t.Fatalf("got %d", w.Code)
	}
}

func TestRoundRobin(t *testing.T) {
	a, b := backend(t, "a", nil), backend(t, "b", nil)
	s := newServer(t, nil)
	counts := map[string]int{}
	for i := 0; i < 10; i++ {
		w := do(t, s, "GET", "http://x/", map[string]string{"X-Detour-Target": a.URL + "," + b.URL, "X-Detour-Key": testKey, "X-Detour-Policy": "roundrobin"})
		counts[w.Body.String()]++
	}
	if counts["a"] != 5 || counts["b"] != 5 {
		t.Fatalf("counts = %v", counts)
	}
	if w := do(t, s, "GET", "http://x/", map[string]string{"X-Detour-Target": a.URL, "X-Detour-Key": testKey, "X-Detour-Policy": "bogus"}); w.Code != http.StatusBadRequest {
		t.Fatalf("bad policy: %d", w.Code)
	}
}

func TestRedirectAndCookieRewrite(t *testing.T) {
	var be *httptest.Server
	be = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "1", Path: "/study/app", HttpOnly: true})
		http.Redirect(w, r, be.URL+"/study/login?next=1", http.StatusFound)
	}))
	defer be.Close()
	s := newServer(t, nil)
	w := do(t, s, "GET", "http://study.example/", map[string]string{"X-Detour-Target": be.URL + "/study", "X-Detour-Key": testKey})
	if loc := w.Header().Get("Location"); loc != "/login?next=1" {
		t.Errorf("Location = %q", loc)
	}
	if c := w.Header().Get("Set-Cookie"); !strings.Contains(c, "Path=/app") {
		t.Errorf("Set-Cookie = %q", c)
	}

	w = do(t, s, "GET", "http://study.example/", map[string]string{"X-Detour-Target": be.URL + "/study", "X-Detour-Key": testKey, "X-Detour-Rewrite-Redirects": "false"})
	if loc := w.Header().Get("Location"); loc != be.URL+"/study/login?next=1" {
		t.Errorf("rewrite disabled, Location = %q", loc)
	}
}

func TestRewriteLocation(t *testing.T) {
	up, _ := url.Parse("http://10.0.0.5:8080/study")
	cases := []struct{ in, strip, want string }{
		{"http://10.0.0.5:8080/study/x", "", "/x"},
		{"/study/x?a=1", "", "/x?a=1"},
		{"/study", "", "/"},
		{"/other", "", "/other"},
		{"http://10.0.0.5:8080/other", "", "/other"},
		{"https://elsewhere.example/study/x", "", "https://elsewhere.example/study/x"},
		{"login", "", "login"},
		{"/study/x", "/api", "/api/x"},
		{"/study", "/api", "/api"},
	}
	for _, c := range cases {
		if got, _ := rewriteLocation(c.in, up, c.strip); got != c.want {
			t.Errorf("rewriteLocation(%q, strip %q) = %q, want %q", c.in, c.strip, got, c.want)
		}
	}
	root, _ := url.Parse("http://10.0.0.5:8080")
	if got, changed := rewriteLocation("/x", root, ""); changed || got != "/x" {
		t.Errorf("root target should leave paths alone: %q", got)
	}
	if got, _ := rewriteLocation("http://10.0.0.5:8080/x", root, ""); got != "/x" {
		t.Errorf("root target should hide upstream origin: %q", got)
	}
}

func TestInsecureTLS(t *testing.T) {
	tlsBE := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "tls") }))
	defer tlsBE.Close()

	strict := newServer(t, nil)
	hdr := map[string]string{"X-Detour-Target": tlsBE.URL, "X-Detour-Key": testKey}
	if w := do(t, strict, "GET", "http://x/", hdr); w.Code != http.StatusBadGateway {
		t.Fatalf("self-signed upstream should fail verification: %d", w.Code)
	}
	hdr["X-Detour-Insecure"] = "true"
	if w := do(t, strict, "GET", "http://x/", hdr); w.Code != http.StatusForbidden {
		t.Fatalf("insecure header must be gated: %d", w.Code)
	}
	lax := newServer(t, func(c *config.Config) { c.AllowInsecureTLS = true })
	if w := do(t, lax, "GET", "http://x/", hdr); w.Code != http.StatusOK || w.Body.String() != "tls" {
		t.Fatalf("insecure allowed: %d %q", w.Code, w.Body.String())
	}
}

func TestDefaultTargetAndOverridesOff(t *testing.T) {
	var got seen
	be := backend(t, "def", &got)
	s := newServer(t, func(c *config.Config) { c.DefaultTarget = be.URL + "/base"; c.AllowOverrides = false })
	w := do(t, s, "GET", "http://x/p", map[string]string{"X-Detour-Key": testKey, "X-Detour-Strip-Prefix": "/p"})
	if w.Code != http.StatusOK || got.path != "/base/p" {
		t.Fatalf("default target: %d path=%s (strip override must be ignored)", w.Code, got.path)
	}
}

func TestWebSocketUpgrade(t *testing.T) {
	be := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "no upgrade", 400)
			return
		}
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		_ = brw.Flush()
		line, _ := brw.ReadString('\n')
		_, _ = brw.WriteString("echo:" + line)
		_ = brw.Flush()
	}))
	defer be.Close()

	front := httptest.NewServer(newServer(t, nil))
	defer front.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(front.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "GET /ws HTTP/1.1\r\nHost: ws.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"X-Detour-Target: " + be.URL + "\r\nX-Detour-Key: " + testKey + "\r\n\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, err := io.WriteString(conn, "hello\n"); err != nil {
		t.Fatal(err)
	}
	line, err := br.ReadString('\n')
	if err != nil || line != "echo:hello\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}
