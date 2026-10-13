// Package target parses upstream target specifications and builds upstream URLs.
//
// A target header value is a list of upstream URLs separated by commas or
// whitespace. Each URL may carry parameters separated by semicolons:
//
//	http://10.0.0.5:8080/app;weight=3, http://10.0.0.6:8080/app;backup
//
// The URL path is the base path: incoming request paths are appended to it.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Target is a single upstream.
type Target struct {
	// URL is the upstream base URL (scheme, host, optional base path and query).
	URL *url.URL
	// Weight is the relative weight for weighted policies (>= 1).
	Weight int
	// Backup targets are only used when no primary target is available.
	Backup bool
}

// Origin returns scheme://host:port, used as the identity for health state.
func (t Target) Origin() string {
	return t.URL.Scheme + "://" + HostPort(t.URL)
}

// String returns the canonical form of the target including parameters.
func (t Target) String() string {
	s := t.URL.String()
	if t.Weight != 1 {
		s += ";weight=" + strconv.Itoa(t.Weight)
	}
	if t.Backup {
		s += ";backup"
	}
	return s
}

// ParseOptions controls what Parse accepts.
type ParseOptions struct {
	// AllowedSchemes lists accepted URL schemes (lowercase). Empty means http and https.
	AllowedSchemes []string
	// MaxTargets is the maximum number of targets in one header (0 = unlimited).
	MaxTargets int
}

// MaxWeight bounds the weight parameter.
const MaxWeight = 1000

// Parse parses a target header value into a list of targets.
func Parse(value string, opts ParseOptions) ([]Target, error) {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(fields) == 0 {
		return nil, errors.New("no target given")
	}
	if opts.MaxTargets > 0 && len(fields) > opts.MaxTargets {
		return nil, fmt.Errorf("too many targets: %d > %d", len(fields), opts.MaxTargets)
	}
	schemes := opts.AllowedSchemes
	if len(schemes) == 0 {
		schemes = []string{"http", "https"}
	}

	out := make([]Target, 0, len(fields))
	for _, f := range fields {
		t, err := parseOne(f, schemes)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func parseOne(spec string, schemes []string) (Target, error) {
	parts := strings.Split(spec, ";")
	raw := strings.TrimSpace(parts[0])
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target %q: %v", raw, err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if !contains(schemes, u.Scheme) {
		return Target{}, fmt.Errorf("target %q: scheme %q not allowed", raw, u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return Target{}, fmt.Errorf("target %q: missing host", raw)
	}
	if u.User != nil {
		return Target{}, fmt.Errorf("target %q: userinfo is not allowed", raw)
	}
	if u.Fragment != "" {
		return Target{}, fmt.Errorf("target %q: fragment is not allowed", raw)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, fmt.Errorf("target %q: invalid port", raw)
		}
	}
	u.Host = strings.ToLower(u.Host)

	t := Target{URL: u, Weight: 1}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key, val, hasVal := strings.Cut(p, "=")
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "weight":
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if !hasVal || err != nil || n < 1 || n > MaxWeight {
				return Target{}, fmt.Errorf("target %q: weight must be 1..%d", raw, MaxWeight)
			}
			t.Weight = n
		case "backup":
			if hasVal {
				b, err := strconv.ParseBool(strings.TrimSpace(val))
				if err != nil {
					return Target{}, fmt.Errorf("target %q: invalid backup value", raw)
				}
				t.Backup = b
			} else {
				t.Backup = true
			}
		default:
			return Target{}, fmt.Errorf("target %q: unknown parameter %q", raw, key)
		}
	}
	return t, nil
}

// HostPort returns host:port of u, filling in the default port for the scheme.
func HostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// BuildURL returns the upstream URL for an incoming request URL: the target base
// path joined with the incoming path (after removing stripPrefix), and the target
// query merged with the incoming query.
func BuildURL(base *url.URL, in *url.URL, stripPrefix string) *url.URL {
	inPath, inRaw := in.Path, in.RawPath
	if stripPrefix != "" && stripPrefix != "/" {
		inPath, inRaw = StripPrefix(inPath, inRaw, stripPrefix)
	}

	out := *base
	out.User = nil
	out.Fragment = ""
	out.Path, out.RawPath = joinURLPath(base.Path, base.RawPath, inPath, inRaw)
	switch {
	case base.RawQuery == "":
		out.RawQuery = in.RawQuery
	case in.RawQuery == "":
		out.RawQuery = base.RawQuery
	default:
		out.RawQuery = base.RawQuery + "&" + in.RawQuery
	}
	return &out
}

// StripPrefix removes prefix from the path if the path starts with it on a
// segment boundary. The result always starts with "/".
func StripPrefix(path, rawPath, prefix string) (string, string) {
	prefix = "/" + strings.Trim(prefix, "/")
	if !hasSegmentPrefix(path, prefix) {
		return path, rawPath
	}
	p := ensureSlash(strings.TrimPrefix(path, prefix))
	r := ""
	if rawPath != "" {
		// The escaped form of the prefix may differ; fall back to the decoded path if so.
		if ep := (&url.URL{Path: prefix}).EscapedPath(); hasSegmentPrefix(rawPath, ep) {
			r = ensureSlash(strings.TrimPrefix(rawPath, ep))
		}
	}
	return p, r
}

func hasSegmentPrefix(path, prefix string) bool {
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

func ensureSlash(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

// joinURLPath joins base and incoming paths with exactly one slash between them,
// keeping RawPath consistent (same semantics as net/http/httputil).
func joinURLPath(aPath, aRaw, bPath, bRaw string) (path, rawpath string) {
	if aRaw == "" && bRaw == "" {
		return singleJoiningSlash(aPath, bPath), ""
	}
	a := (&url.URL{Path: aPath, RawPath: aRaw}).EscapedPath()
	b := (&url.URL{Path: bPath, RawPath: bRaw}).EscapedPath()
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return aPath + bPath[1:], a + b[1:]
	case !aslash && !bslash:
		return aPath + "/" + bPath, a + "/" + b
	}
	return aPath + bPath, a + b
}

func singleJoiningSlash(a, b string) string {
	if a == "" {
		a = "/"
	}
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
