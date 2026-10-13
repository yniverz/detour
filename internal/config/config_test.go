package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yniverz/detour/internal/balancer"
)

func envMap(m map[string]string) Getenv {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDefaultsRequireKeysAndAllowlist(t *testing.T) {
	_, err := LoadFrom(envMap(nil))
	if err == nil {
		t.Fatal("empty config must be rejected")
	}
	for _, want := range []string{"no keys configured", "no target allowlist"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "keys")
	if err := os.WriteFile(keyFile, []byte("# comment\nfilekey\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadFrom(envMap(map[string]string{
		"DETOUR_KEYS":            "k1, k2",
		"DETOUR_KEYS_FILE":       keyFile,
		"DETOUR_ALLOWED_TARGETS": "10.0.0.0/8 *.lan",
		"DETOUR_DEFAULT_POLICY":  "sticky",
		"DETOUR_FAIL_TIMEOUT":    "30",
		"DETOUR_FAIL_STATUS":     "502,503",
		"DETOUR_HEADER_PREFIX":   "x-edge-",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Keys) != 3 || c.Keys[2] != "filekey" {
		t.Errorf("keys = %v", c.Keys)
	}
	if c.DefaultPolicy != balancer.IPHash || c.FailTimeout != 30*time.Second || len(c.FailStatus) != 2 {
		t.Errorf("parsed = %+v", c)
	}
	if c.HeaderTarget() != "X-Edge-Target" {
		t.Errorf("header = %s", c.HeaderTarget())
	}
	if c.Listen != ":8080" || c.HostMode != HostIncoming || c.Forwarded != ForwardedAppend || !c.RewriteRedirects {
		t.Errorf("defaults wrong: %+v", c)
	}
}

func TestInvalidValues(t *testing.T) {
	_, err := LoadFrom(envMap(map[string]string{
		"DETOUR_AUTH_DISABLED":    "true",
		"DETOUR_ALLOW_ANY_TARGET": "yes-please",
		"DETOUR_HOST_MODE":        "sometimes",
		"DETOUR_DIAL_TIMEOUT":     "soon",
		"DETOUR_TLS_CERT_FILE":    "/x.pem",
	}))
	if err == nil {
		t.Fatal("invalid values accepted")
	}
	for _, want := range []string{"DETOUR_ALLOW_ANY_TARGET", "DETOUR_DIAL_TIMEOUT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}
