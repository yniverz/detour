package guard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestKeys(t *testing.T) {
	k := NewKeys([]string{"alpha", " beta ", ""})
	if k.Len() != 2 {
		t.Fatalf("len = %d", k.Len())
	}
	for key, want := range map[string]bool{"alpha": true, "beta": true, "": false, "alph": false, "gamma": false} {
		if got := k.Valid(key); got != want {
			t.Errorf("Valid(%q) = %v", key, got)
		}
	}
}

func TestPrefixSet(t *testing.T) {
	ps, err := ParsePrefixes([]string{"10.20.30.0/24", "192.168.1.7", "fd00::/8"})
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"10.20.30.9": true, "10.20.31.1": false, "192.168.1.7": true, "::ffff:10.20.30.1": true, "fd12::1": true} {
		if got := ps.Contains(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Contains(%s) = %v", ip, got)
		}
	}
	if _, err := ParsePrefixes([]string{"10.0.0.0/33"}); err == nil {
		t.Error("invalid CIDR accepted")
	}
}

func TestTargetPolicy(t *testing.T) {
	tp, err := ParseTargetPolicy([]string{"10.0.0.0/8", "*.internal", "backend.lan"}, false)
	if err != nil {
		t.Fatal(err)
	}
	ok := []string{"10.1.2.3", "app.internal", "a.b.internal", "backend.lan", "BACKEND.LAN", "somehost.example"}
	for _, h := range ok {
		if err := tp.CheckHost(h); err != nil {
			t.Errorf("CheckHost(%s) = %v", h, err)
		}
	}
	for _, h := range []string{"192.168.1.1", "::1"} {
		if err := tp.CheckHost(h); err == nil {
			t.Errorf("CheckHost(%s) allowed", h)
		}
	}
	if tp.HostTrusted("internal") || tp.HostTrusted("evilinternal") {
		t.Error("wildcard matched too much")
	}

	hostsOnly, _ := ParseTargetPolicy([]string{"*.internal"}, false)
	if err := hostsOnly.CheckHost("other.example"); err == nil {
		t.Error("hostname outside patterns allowed without prefixes")
	}
	if _, err := ParseTargetPolicy([]string{"*"}, false); err == nil {
		t.Error("bare wildcard accepted")
	}
}

func TestDialerEnforcesPrefixes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	deny, _ := ParseTargetPolicy([]string{"10.0.0.0/8"}, false)
	_, err = deny.Dialer(time.Second, 0, nil)(context.Background(), "tcp", "127.0.0.1:"+port)
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("expected ErrTargetNotAllowed, got %v", err)
	}
	// "localhost" passes the request-time check (prefixes exist) but must fail at dial time.
	_, err = deny.Dialer(time.Second, 0, nil)(context.Background(), "tcp", "localhost:"+port)
	if !errors.Is(err, ErrTargetNotAllowed) {
		t.Fatalf("expected ErrTargetNotAllowed for localhost, got %v", err)
	}

	allow, _ := ParseTargetPolicy([]string{"127.0.0.0/8"}, false)
	c, err := allow.Dialer(time.Second, 0, nil)(context.Background(), "tcp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	byName, _ := ParseTargetPolicy([]string{"localhost"}, false)
	c, err = byName.Dialer(time.Second, 0, nil)(context.Background(), "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("host pattern should bypass IP check: %v", err)
	}
	c.Close()
}
