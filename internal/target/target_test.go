package target

import (
	"net/url"
	"testing"
)

func TestParse(t *testing.T) {
	ts, err := Parse("http://10.0.0.5:8080/app;weight=3, HTTPS://Backend.LAN/;backup  http://h2", ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 3 {
		t.Fatalf("want 3 targets, got %d", len(ts))
	}
	if ts[0].Weight != 3 || ts[0].Backup || ts[0].URL.Path != "/app" {
		t.Errorf("target 0 = %+v", ts[0])
	}
	if !ts[1].Backup || ts[1].URL.Scheme != "https" || ts[1].URL.Host != "backend.lan" {
		t.Errorf("target 1 = %+v %s", ts[1], ts[1].URL)
	}
	if ts[1].Origin() != "https://backend.lan:443" || ts[2].Origin() != "http://h2:80" {
		t.Errorf("origins: %s %s", ts[1].Origin(), ts[2].Origin())
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{
		"",
		"ftp://x",
		"http://",
		"http://user:pw@x",
		"http://x#frag",
		"http://x:99999",
		"http://x;weight=0",
		"http://x;weight=abc",
		"http://x;unknown=1",
		"not a url at all%%",
	} {
		if _, err := Parse(in, ParseOptions{}); err == nil {
			t.Errorf("Parse(%q) should fail", in)
		}
	}
	if _, err := Parse("http://a,http://b,http://c", ParseOptions{MaxTargets: 2}); err == nil {
		t.Error("MaxTargets not enforced")
	}
	if _, err := Parse("http://a", ParseOptions{AllowedSchemes: []string{"https"}}); err == nil {
		t.Error("AllowedSchemes not enforced")
	}
}

func TestBuildURL(t *testing.T) {
	cases := []struct {
		base, in, strip, want string
	}{
		{"http://h:80", "/page?x=1", "", "http://h:80/page?x=1"},
		{"http://h:80/", "/page", "", "http://h:80/page"},
		{"http://h:80/study", "/", "", "http://h:80/study/"},
		{"http://h:80/study", "/page?x=1", "", "http://h:80/study/page?x=1"},
		{"http://h:80/study/", "/page", "", "http://h:80/study/page"},
		{"http://h/a?k=v", "/b?x=1", "", "http://h/a/b?k=v&x=1"},
		{"http://h/a?k=v", "/b", "", "http://h/a/b?k=v"},
		{"http://h/study", "/api/page", "/api", "http://h/study/page"},
		{"http://h/study", "/api", "/api/", "http://h/study/"},
		{"http://h/study", "/apiary", "/api", "http://h/study/apiary"},
		{"http://h/x", "/a%2Fb", "", "http://h/x/a%2Fb"},
	}
	for _, c := range cases {
		base, _ := url.Parse(c.base)
		in, _ := url.Parse(c.in)
		if got := BuildURL(base, in, c.strip).String(); got != c.want {
			t.Errorf("BuildURL(%s, %s, %q) = %s, want %s", c.base, c.in, c.strip, got, c.want)
		}
	}
}
