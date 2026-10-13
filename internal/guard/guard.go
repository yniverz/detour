// Package guard implements detour's access checks: shared keys, trusted request
// sources and the upstream target allowlist (enforced again at dial time).
package guard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Keys holds accepted shared keys. Comparison is constant-time.
type Keys struct {
	hashes [][32]byte
}

// NewKeys builds a key set; empty entries are ignored.
func NewKeys(keys []string) *Keys {
	k := &Keys{}
	for _, s := range keys {
		if s = strings.TrimSpace(s); s != "" {
			k.hashes = append(k.hashes, sha256.Sum256([]byte(s)))
		}
	}
	return k
}

// Len returns the number of configured keys.
func (k *Keys) Len() int { return len(k.hashes) }

// Valid reports whether key matches any configured key.
func (k *Keys) Valid(key string) bool {
	if key == "" {
		return false
	}
	h := sha256.Sum256([]byte(key))
	ok := 0
	for i := range k.hashes {
		ok |= subtle.ConstantTimeCompare(h[:], k.hashes[i][:])
	}
	return ok == 1
}

// PrefixSet is a list of IP prefixes.
type PrefixSet []netip.Prefix

// ParsePrefixes parses CIDRs or single IPs.
func ParsePrefixes(items []string) (PrefixSet, error) {
	var out PrefixSet
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := parsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %v", s, err)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP %q: %v", s, err)
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}

// Contains reports whether ip is inside any prefix.
func (ps PrefixSet) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range ps {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// RemoteIP extracts the IP from an http.Request.RemoteAddr style "host:port".
func RemoteIP(remoteAddr string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(remoteAddr); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// TargetPolicy decides which upstream hosts may be contacted.
//
// A host is allowed when it matches a host pattern, or when it is an IP (or
// resolves to IPs) inside an allowed prefix. For hostnames that only qualify via
// prefixes, the resolved IP is checked again when the connection is dialed, so
// DNS answers cannot redirect detour outside the allowlist.
type TargetPolicy struct {
	AllowAny bool
	Prefixes PrefixSet
	// Hosts are exact hostnames ("app.internal") or suffix wildcards ("*.internal").
	Hosts []string
}

// ParseTargetPolicy splits allowlist entries into prefixes and host patterns.
func ParseTargetPolicy(entries []string, allowAny bool) (*TargetPolicy, error) {
	tp := &TargetPolicy{AllowAny: allowAny}
	for _, e := range entries {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if p, err := parsePrefix(e); err == nil {
			tp.Prefixes = append(tp.Prefixes, p)
			continue
		}
		if strings.Contains(e, "/") {
			return nil, fmt.Errorf("invalid allowlist entry %q", e)
		}
		host := strings.TrimPrefix(e, "*.")
		if host == "" || strings.ContainsAny(host, "*:") {
			return nil, fmt.Errorf("invalid host pattern %q (use host or *.suffix)", e)
		}
		tp.Hosts = append(tp.Hosts, e)
	}
	return tp, nil
}

// Empty reports whether nothing at all would be allowed.
func (tp *TargetPolicy) Empty() bool {
	return !tp.AllowAny && len(tp.Prefixes) == 0 && len(tp.Hosts) == 0
}

// HostTrusted reports whether host matches a host pattern (no IP check needed).
func (tp *TargetPolicy) HostTrusted(host string) bool {
	if tp.AllowAny {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range tp.Hosts {
		if strings.HasPrefix(h, "*.") {
			if strings.HasSuffix(host, h[1:]) && len(host) > len(h)-1 {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}

// ErrTargetNotAllowed is returned for disallowed upstreams.
var ErrTargetNotAllowed = errors.New("target not allowed")

// CheckHost is the request-time check. IP literals must be inside a prefix;
// hostnames must match a pattern or be resolvable within prefixes at dial time.
func (tp *TargetPolicy) CheckHost(host string) error {
	if tp.HostTrusted(host) {
		return nil
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if tp.Prefixes.Contains(a) {
			return nil
		}
		return ErrTargetNotAllowed
	}
	if len(tp.Prefixes) > 0 {
		return nil // verified at dial time
	}
	return ErrTargetNotAllowed
}

// Dialer returns a DialContext function that enforces the policy on the actual
// IP addresses being connected to.
func (tp *TargetPolicy) Dialer(timeout, keepAlive time.Duration, resolver *net.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, KeepAlive: keepAlive}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if tp.HostTrusted(host) {
			return d.DialContext(ctx, network, addr)
		}
		var ips []netip.Addr
		if a, err := netip.ParseAddr(host); err == nil {
			ips = []netip.Addr{a}
		} else {
			ips, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
		}
		var lastErr error = fmt.Errorf("%w: %s resolves only to disallowed addresses", ErrTargetNotAllowed, host)
		for _, ip := range ips {
			if !tp.Prefixes.Contains(ip) {
				continue
			}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return c, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
