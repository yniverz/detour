package proxy

import (
	"net/url"
	"strings"

	"github.com/yniverz/detour/internal/target"
)

// The upstream sees paths as   basePath + (clientPath - stripPrefix).
// Responses are mapped back:   clientPath = stripPrefix + (upstreamPath - basePath).

func normPrefix(p string) string {
	p = "/" + strings.Trim(p, "/")
	if p == "/" {
		return ""
	}
	return p
}

// toClientPath maps an upstream path back to the client-facing path. ok is false
// when the path lies outside the upstream base path.
func toClientPath(upPath, basePath, stripPrefix string) (string, bool) {
	base := normPrefix(basePath)
	rest := upPath
	if base != "" {
		if !(upPath == base || strings.HasPrefix(upPath, base+"/")) {
			return "", false
		}
		rest = strings.TrimPrefix(upPath, base)
	}
	if rest == "" || rest[0] != '/' {
		rest = "/" + rest
	}
	if sp := normPrefix(stripPrefix); sp != "" {
		if rest == "/" && !strings.HasSuffix(upPath, "/") {
			return sp, true
		}
		return sp + rest, true
	}
	return rest, true
}

// rewriteLocation rewrites redirects that point at the upstream (absolute URL with
// the upstream's origin, or an absolute path under its base path) into a
// host-relative client path, so the client stays on the public hostname.
func rewriteLocation(loc string, up *url.URL, stripPrefix string) (string, bool) {
	u, err := url.Parse(loc)
	if err != nil {
		return loc, false
	}
	switch {
	case u.IsAbs() || strings.HasPrefix(loc, "//"):
		if u.Host == "" || !sameOrigin(u, up) {
			return loc, false
		}
	case strings.HasPrefix(u.Path, "/"):
		if normPrefix(up.Path) == "" && normPrefix(stripPrefix) == "" {
			return loc, false
		}
	default:
		return loc, false // relative reference: resolves correctly on its own
	}
	p, ok := toClientPath(u.Path, up.Path, stripPrefix)
	if !ok {
		if u.IsAbs() || strings.HasPrefix(loc, "//") {
			p = u.Path // same origin but outside base: still hide the upstream host
			if p == "" {
				p = "/"
			}
		} else {
			return loc, false
		}
	}
	out := &url.URL{Path: p, RawQuery: u.RawQuery, Fragment: u.Fragment}
	return out.String(), out.String() != loc
}

func sameOrigin(a, b *url.URL) bool {
	if a.Scheme != "" && !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	ac := &url.URL{Scheme: b.Scheme, Host: strings.ToLower(a.Host)}
	if a.Scheme != "" {
		ac.Scheme = strings.ToLower(a.Scheme)
	}
	return target.HostPort(ac) == target.HostPort(b)
}

// rewriteCookiePath rewrites the Path attribute of a Set-Cookie value from the
// upstream base path to the client-facing path.
func rewriteCookiePath(cookie, basePath, stripPrefix string) string {
	if normPrefix(basePath) == "" && normPrefix(stripPrefix) == "" {
		return cookie
	}
	parts := strings.Split(cookie, ";")
	for i := 1; i < len(parts); i++ {
		k, v, ok := strings.Cut(parts[i], "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "path") {
			continue
		}
		val := strings.TrimSpace(v)
		if !strings.HasPrefix(val, "/") {
			continue
		}
		if np, ok := toClientPath(val, basePath, stripPrefix); ok {
			lead := k[:len(k)-len(strings.TrimLeft(k, " "))]
			parts[i] = lead + strings.TrimSpace(k) + "=" + np
		}
	}
	return strings.Join(parts, ";")
}
