package balancer

import (
	"fmt"
	"testing"
	"time"

	"github.com/yniverz/detour/internal/target"
)

func mustParse(t *testing.T, s string) []target.Target {
	t.Helper()
	ts, err := target.Parse(s, target.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func TestSmoothWeightedRoundRobin(t *testing.T) {
	b := New(NewHealth(1, time.Minute), 0)
	ts := mustParse(t, "http://a;weight=3,http://b")
	counts := map[string]int{}
	var seq []string
	for i := 0; i < 8; i++ {
		first := b.Order(ts, RoundRobin, "")[0].URL.Host
		counts[first]++
		seq = append(seq, first)
	}
	if counts["a"] != 6 || counts["b"] != 2 {
		t.Fatalf("counts = %v (seq %v)", counts, seq)
	}
	// Smooth: b must not be picked twice in a row and a never more than 3 times in a row.
	for i := 1; i < len(seq); i++ {
		if seq[i] == "b" && seq[i-1] == "b" {
			t.Fatalf("not smooth: %v", seq)
		}
	}
}

func TestFailoverAndBackup(t *testing.T) {
	h := NewHealth(1, time.Minute)
	b := New(h, 0)
	ts := mustParse(t, "http://a,http://b,http://c;backup")

	order := b.Order(ts, Failover, "")
	if order[0].URL.Host != "a" || order[1].URL.Host != "b" || order[2].URL.Host != "c" {
		t.Fatalf("order = %v", hosts(order))
	}
	h.Failure("http://a:80", time.Now())
	order = b.Order(ts, Failover, "")
	if got := hosts(order); got != "b,c,a" {
		t.Fatalf("after a down: %s", got)
	}
	h.Failure("http://b:80", time.Now())
	if got := hosts(b.Order(ts, Failover, "")); got != "c,a,b" {
		t.Fatalf("after a,b down: %s", got)
	}
	h.Success("http://a:80")
	if got := hosts(b.Order(ts, Failover, "")); got != "a,c,b" {
		t.Fatalf("after a recovered: %s", got)
	}
}

func TestHealthRecoversAfterTimeout(t *testing.T) {
	h := NewHealth(2, 50*time.Millisecond)
	now := time.Now()
	if h.Failure("o", now) {
		t.Fatal("marked down after 1 of 2 fails")
	}
	if !h.Failure("o", now) {
		t.Fatal("not marked down after 2 fails")
	}
	if h.Available("o", now.Add(10*time.Millisecond)) {
		t.Fatal("available while down")
	}
	if !h.Available("o", now.Add(60*time.Millisecond)) {
		t.Fatal("not available after timeout")
	}
}

func TestIPHashSticky(t *testing.T) {
	h := NewHealth(1, time.Minute)
	b := New(h, 0)
	ts := mustParse(t, "http://a,http://b,http://c")
	seen := map[string]bool{}
	for _, client := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5", "6.6.6.6"} {
		first := b.Order(ts, IPHash, client)[0].URL.Host
		for i := 0; i < 5; i++ {
			if again := b.Order(ts, IPHash, client)[0].URL.Host; again != first {
				t.Fatalf("client %s moved from %s to %s", client, first, again)
			}
		}
		seen[first] = true
	}
	if len(seen) < 2 {
		t.Fatalf("iphash put every client on the same upstream: %v", seen)
	}
	// Marking one upstream down only moves its own clients.
	victim := b.Order(ts, IPHash, "1.1.1.1")[0]
	other := "2.2.2.2"
	for b.Order(ts, IPHash, other)[0].URL.Host == victim.URL.Host {
		other += "0"
	}
	before := b.Order(ts, IPHash, other)[0].URL.Host
	h.Failure(victim.Origin(), time.Now())
	if b.Order(ts, IPHash, "1.1.1.1")[0].URL.Host == victim.URL.Host {
		t.Fatal("client stayed on a down upstream")
	}
	if after := b.Order(ts, IPHash, other)[0].URL.Host; after != before {
		t.Fatalf("unrelated client moved from %s to %s", before, after)
	}
}

func TestIPHashDistribution(t *testing.T) {
	b := New(NewHealth(1, time.Minute), 0)
	ts := mustParse(t, "http://a,http://b,http://c;weight=2")
	counts := map[string]int{}
	const n = 4000
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)
		counts[b.Order(ts, IPHash, ip)[0].URL.Host]++
	}
	// Expected shares 25% / 25% / 50%; allow generous tolerance.
	for host, want := range map[string]float64{"a": 0.25, "b": 0.25, "c": 0.5} {
		got := float64(counts[host]) / n
		if got < want-0.05 || got > want+0.05 {
			t.Errorf("host %s got %.3f of clients, want ~%.2f (%v)", host, got, want, counts)
		}
	}
}

func TestLeastConn(t *testing.T) {
	h := NewHealth(1, time.Minute)
	b := New(h, 0)
	ts := mustParse(t, "http://a,http://b")
	release := h.Acquire("http://a:80")
	if first := b.Order(ts, LeastConn, "")[0].URL.Host; first != "b" {
		t.Fatalf("leastconn picked %s", first)
	}
	release()
	release() // idempotent
	if first := b.Order(ts, LeastConn, "")[0].URL.Host; first != "a" {
		t.Fatalf("leastconn picked %s after release", first)
	}
}

func TestParsePolicy(t *testing.T) {
	for in, want := range map[string]Policy{"RR": RoundRobin, "sticky": IPHash, "first": Failover, "leastconn": LeastConn, "random": Random} {
		if got, err := ParsePolicy(in); err != nil || got != want {
			t.Errorf("ParsePolicy(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParsePolicy("weird"); err == nil {
		t.Error("unknown policy accepted")
	}
}

func hosts(ts []target.Target) string {
	s := ""
	for i, t := range ts {
		if i > 0 {
			s += ","
		}
		s += t.URL.Host
	}
	return s
}
