package sniff

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/yniverz/detour/internal/selfsigned"
)

func TestPlainAndTLSOnSamePort(t *testing.T) {
	cert, err := selfsigned.Generate([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := New(inner, tlsConf, time.Second)
	srv := &http.Server{
		TLSConfig: tlsConf,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			_, _ = io.WriteString(w, scheme+" "+r.Proto)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	// A silent client must not block other connections.
	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()

	addr := ln.Addr().String()
	get := func(c *http.Client, url string) string {
		t.Helper()
		resp, err := c.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	if got := get(&http.Client{Timeout: 3 * time.Second}, "http://"+addr+"/"); got != "http HTTP/1.1" {
		t.Errorf("plain: %q", got)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert.Leaf)
	h2 := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: true}}
	if got := get(h2, "https://"+addr+"/"); got != "https HTTP/2.0" {
		t.Errorf("tls: %q", got)
	}
	h1 := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}}
	if got := get(h1, "https://"+addr+"/"); got != "https HTTP/1.1" {
		t.Errorf("tls http/1.1: %q", got)
	}
}

func TestSilentClientTimesOut(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := New(inner, &tls.Config{}, 100*time.Millisecond)
	defer ln.Close()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent connection was not closed")
	}
}

func TestCloseUnblocksAccept(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := New(inner, &tls.Config{}, time.Second)
	errc := make(chan error, 1)
	go func() { _, err := ln.Accept(); errc <- err }()
	time.Sleep(50 * time.Millisecond)
	ln.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("Accept returned nil error after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}
