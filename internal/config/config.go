// Package config loads detour's configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yniverz/detour/internal/balancer"
)

// HostMode decides which Host header is sent upstream.
type HostMode string

const (
	HostIncoming HostMode = "incoming" // keep the Host header of the incoming request
	HostTarget   HostMode = "target"   // use the upstream's host:port
)

// ForwardedMode controls X-Forwarded-* handling.
type ForwardedMode string

const (
	ForwardedAppend   ForwardedMode = "append"   // append peer IP to X-Forwarded-For, keep incoming -Host/-Proto or set them
	ForwardedPreserve ForwardedMode = "preserve" // pass incoming X-Forwarded-* through unchanged
	ForwardedNone     ForwardedMode = "none"     // remove X-Forwarded-* entirely
)

// Config is the complete runtime configuration.
type Config struct {
	Listen            string
	TLSCertFile       string
	TLSKeyFile        string
	TLSSelfSigned     bool
	TLSSelfSigHosts   []string
	AdminListen       string
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration

	HeaderPrefix string

	Keys           []string
	AuthDisabled   bool
	TrustedSources []string

	AllowedTargets   []string
	AllowAnyTarget   bool
	AllowedSchemes   []string
	MaxTargets       int
	DefaultTarget    string
	AllowInsecureTLS bool // allow the per-request insecure header
	InsecureTLS      bool // skip upstream certificate verification by default
	CAFile           string

	DefaultPolicy     balancer.Policy
	HostMode          HostMode
	RewriteRedirects  bool
	RewriteCookiePath bool
	Forwarded         ForwardedMode
	ClientIPHeader    string
	AllowOverrides    bool // allow per-request policy/host/strip/rewrite headers

	MaxFails      int
	FailTimeout   time.Duration
	FailStatus    []int
	Retries       int // -1 = try every candidate
	MaxPools      int
	DialTimeout   time.Duration
	RespHdrTO     time.Duration
	IdleConnTO    time.Duration
	MaxIdlePerHst int
	FlushInterval time.Duration

	LogLevel       string
	LogFormat      string
	AccessLog      bool
	ExposeUpstream bool
}

// TLSEnabled reports whether the proxy listener serves HTTPS.
func (c *Config) TLSEnabled() bool { return c.TLSSelfSigned || c.TLSCertFile != "" }

// Header names derived from the prefix.
func (c *Config) HeaderTarget() string           { return c.HeaderPrefix + "Target" }
func (c *Config) HeaderKey() string              { return c.HeaderPrefix + "Key" }
func (c *Config) HeaderPolicy() string           { return c.HeaderPrefix + "Policy" }
func (c *Config) HeaderHost() string             { return c.HeaderPrefix + "Host" }
func (c *Config) HeaderStripPrefix() string      { return c.HeaderPrefix + "Strip-Prefix" }
func (c *Config) HeaderInsecure() string         { return c.HeaderPrefix + "Insecure" }
func (c *Config) HeaderRewriteRedirects() string { return c.HeaderPrefix + "Rewrite-Redirects" }
func (c *Config) HeaderUpstream() string         { return c.HeaderPrefix + "Upstream" }

// Getenv is the lookup function; replaceable in tests.
type Getenv func(string) (string, bool)

// Load reads the configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.LookupEnv) }

// LoadFrom reads the configuration using env.
func LoadFrom(env Getenv) (*Config, error) {
	p := &parser{env: env}
	c := &Config{
		Listen:            p.str("DETOUR_LISTEN", ":8080"),
		TLSCertFile:       p.str("DETOUR_TLS_CERT_FILE", ""),
		TLSKeyFile:        p.str("DETOUR_TLS_KEY_FILE", ""),
		TLSSelfSigned:     p.boolean("DETOUR_TLS_SELF_SIGNED", false),
		TLSSelfSigHosts:   p.list("DETOUR_TLS_SELF_SIGNED_HOSTS"),
		AdminListen:       p.str("DETOUR_ADMIN_LISTEN", ""),
		ReadHeaderTimeout: p.dur("DETOUR_READ_HEADER_TIMEOUT", 10*time.Second),
		IdleTimeout:       p.dur("DETOUR_IDLE_TIMEOUT", 120*time.Second),
		ShutdownTimeout:   p.dur("DETOUR_SHUTDOWN_TIMEOUT", 15*time.Second),

		HeaderPrefix: p.str("DETOUR_HEADER_PREFIX", "X-Detour-"),

		Keys:           p.secretList("DETOUR_KEYS"),
		AuthDisabled:   p.boolean("DETOUR_AUTH_DISABLED", false),
		TrustedSources: p.list("DETOUR_TRUSTED_SOURCES"),

		AllowedTargets:   p.list("DETOUR_ALLOWED_TARGETS"),
		AllowAnyTarget:   p.boolean("DETOUR_ALLOW_ANY_TARGET", false),
		AllowedSchemes:   lower(p.listDefault("DETOUR_ALLOWED_SCHEMES", []string{"http", "https"})),
		MaxTargets:       p.integer("DETOUR_MAX_TARGETS", 16),
		DefaultTarget:    p.str("DETOUR_DEFAULT_TARGET", ""),
		AllowInsecureTLS: p.boolean("DETOUR_ALLOW_INSECURE_TLS", false),
		InsecureTLS:      p.boolean("DETOUR_TLS_INSECURE_SKIP_VERIFY", false),
		CAFile:           p.str("DETOUR_CA_FILE", ""),

		HostMode:          HostMode(strings.ToLower(p.str("DETOUR_HOST_MODE", string(HostIncoming)))),
		RewriteRedirects:  p.boolean("DETOUR_REWRITE_REDIRECTS", true),
		RewriteCookiePath: p.boolean("DETOUR_REWRITE_COOKIE_PATH", true),
		Forwarded:         ForwardedMode(strings.ToLower(p.str("DETOUR_FORWARDED", string(ForwardedAppend)))),
		ClientIPHeader:    p.str("DETOUR_CLIENT_IP_HEADER", ""),
		AllowOverrides:    p.boolean("DETOUR_ALLOW_OVERRIDES", true),

		MaxFails:      p.integer("DETOUR_MAX_FAILS", 1),
		FailTimeout:   p.dur("DETOUR_FAIL_TIMEOUT", 10*time.Second),
		FailStatus:    p.ints("DETOUR_FAIL_STATUS"),
		Retries:       p.integer("DETOUR_RETRIES", -1),
		MaxPools:      p.integer("DETOUR_MAX_POOLS", 1024),
		DialTimeout:   p.dur("DETOUR_DIAL_TIMEOUT", 5*time.Second),
		RespHdrTO:     p.dur("DETOUR_RESPONSE_HEADER_TIMEOUT", 0),
		IdleConnTO:    p.dur("DETOUR_IDLE_CONN_TIMEOUT", 90*time.Second),
		MaxIdlePerHst: p.integer("DETOUR_MAX_IDLE_CONNS_PER_HOST", 32),
		FlushInterval: p.dur("DETOUR_FLUSH_INTERVAL", 0),

		LogLevel:       strings.ToLower(p.str("DETOUR_LOG_LEVEL", "info")),
		LogFormat:      strings.ToLower(p.str("DETOUR_LOG_FORMAT", "text")),
		AccessLog:      p.boolean("DETOUR_ACCESS_LOG", true),
		ExposeUpstream: p.boolean("DETOUR_EXPOSE_UPSTREAM", false),
	}
	pol, err := balancer.ParsePolicy(p.str("DETOUR_DEFAULT_POLICY", string(balancer.RoundRobin)))
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("DETOUR_DEFAULT_POLICY: %w", err))
	}
	c.DefaultPolicy = pol

	if len(p.errs) > 0 {
		return nil, errors.Join(p.errs...)
	}
	return c, c.Validate()
}

// Validate checks consistency and refuses insecure combinations unless explicitly enabled.
func (c *Config) Validate() error {
	var errs []error
	if !c.AuthDisabled && len(c.Keys) == 0 {
		errs = append(errs, errors.New("no keys configured: set DETOUR_KEYS / DETOUR_KEYS_FILE, or DETOUR_AUTH_DISABLED=true (only safe with DETOUR_TRUSTED_SOURCES)"))
	}
	if !c.AllowAnyTarget && len(c.AllowedTargets) == 0 {
		errs = append(errs, errors.New("no target allowlist: set DETOUR_ALLOWED_TARGETS, or DETOUR_ALLOW_ANY_TARGET=true"))
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, errors.New("DETOUR_TLS_CERT_FILE and DETOUR_TLS_KEY_FILE must be set together"))
	}
	if c.TLSSelfSigned && c.TLSCertFile != "" {
		errs = append(errs, errors.New("DETOUR_TLS_SELF_SIGNED cannot be combined with DETOUR_TLS_CERT_FILE/DETOUR_TLS_KEY_FILE"))
	}
	if c.HeaderPrefix == "" || !validHeaderToken(c.HeaderPrefix) {
		errs = append(errs, fmt.Errorf("DETOUR_HEADER_PREFIX %q is not a valid header name prefix", c.HeaderPrefix))
	}
	c.HeaderPrefix = http.CanonicalHeaderKey(c.HeaderPrefix)
	if c.HostMode != HostIncoming && c.HostMode != HostTarget {
		errs = append(errs, fmt.Errorf("DETOUR_HOST_MODE must be incoming or target, got %q", c.HostMode))
	}
	switch c.Forwarded {
	case ForwardedAppend, ForwardedPreserve, ForwardedNone:
	default:
		errs = append(errs, fmt.Errorf("DETOUR_FORWARDED must be append, preserve or none, got %q", c.Forwarded))
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("DETOUR_LOG_FORMAT must be text or json, got %q", c.LogFormat))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("DETOUR_LOG_LEVEL must be debug, info, warn or error, got %q", c.LogLevel))
	}
	for _, s := range c.AllowedSchemes {
		if s != "http" && s != "https" {
			errs = append(errs, fmt.Errorf("DETOUR_ALLOWED_SCHEMES: unsupported scheme %q", s))
		}
	}
	if c.MaxTargets < 1 {
		errs = append(errs, errors.New("DETOUR_MAX_TARGETS must be >= 1"))
	}
	for _, s := range c.FailStatus {
		if s < 100 || s > 599 {
			errs = append(errs, fmt.Errorf("DETOUR_FAIL_STATUS: invalid status %d", s))
		}
	}
	return errors.Join(errs...)
}

func validHeaderToken(s string) bool {
	for _, r := range s {
		if !(r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

type parser struct {
	env  Getenv
	errs []error
}

func (p *parser) raw(name string) (string, bool) {
	v, ok := p.env(name)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(v), true
}

func (p *parser) str(name, def string) string {
	if v, ok := p.raw(name); ok && v != "" {
		return v
	}
	return def
}

func (p *parser) boolean(name string, def bool) bool {
	v, ok := p.raw(name)
	if !ok || v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: invalid boolean %q", name, v))
		return def
	}
	return b
}

func (p *parser) integer(name string, def int) int {
	v, ok := p.raw(name)
	if !ok || v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		p.errs = append(p.errs, fmt.Errorf("%s: invalid integer %q", name, v))
		return def
	}
	return n
}

func (p *parser) dur(name string, def time.Duration) time.Duration {
	v, ok := p.raw(name)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		if n, err2 := strconv.Atoi(v); err2 == nil {
			return time.Duration(n) * time.Second
		}
		p.errs = append(p.errs, fmt.Errorf("%s: invalid duration %q", name, v))
		return def
	}
	return d
}

func (p *parser) list(name string) []string {
	v, _ := p.raw(name)
	return splitList(v)
}

func (p *parser) listDefault(name string, def []string) []string {
	if l := p.list(name); len(l) > 0 {
		return l
	}
	return def
}

func (p *parser) ints(name string) []int {
	var out []int
	for _, s := range p.list(name) {
		n, err := strconv.Atoi(s)
		if err != nil {
			p.errs = append(p.errs, fmt.Errorf("%s: invalid integer %q", name, s))
			continue
		}
		out = append(out, n)
	}
	return out
}

// secretList reads NAME (comma separated) plus NAME_FILE (one entry per line,
// '#' comments allowed), e.g. for Docker secrets.
func (p *parser) secretList(name string) []string {
	out := p.list(name)
	if path, ok := p.raw(name + "_FILE"); ok && path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			p.errs = append(p.errs, fmt.Errorf("%s_FILE: %v", name, err))
			return out
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				out = append(out, line)
			}
		}
	}
	return out
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func lower(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}
