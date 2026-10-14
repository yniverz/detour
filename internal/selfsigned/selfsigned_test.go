package selfsigned

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGenerateAndServe(t *testing.T) {
	cert, err := Generate([]string{"detour.lan", "127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Leaf.DNSNames; len(got) != 1 || got[0] != "detour.lan" {
		t.Errorf("DNSNames = %v", got)
	}
	if len(cert.Leaf.IPAddresses) != 1 || !cert.Leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Errorf("IPAddresses = %v", cert.Leaf.IPAddresses)
	}
	if fp := Fingerprint(cert); len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Errorf("fingerprint format: %s", fp)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// A client that trusts exactly this certificate verifies it for the IP SAN.
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := c.Get("https://" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
		t.Fatalf("body %q", b)
	}
}

func TestDefaultHosts(t *testing.T) {
	h := DefaultHosts()
	found := false
	for _, x := range h {
		if x == "localhost" {
			found = true
		}
	}
	if !found {
		t.Errorf("localhost missing from %v", h)
	}
}
