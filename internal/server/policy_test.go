package server

import (
	"net"
	"testing"
)

func TestTargetPolicyDefaultDeny(t *testing.T) {
	p, err := newTargetPolicy("")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"127.0.0.1", false},
		{"10.0.0.5", false},
		{"172.16.5.4", false},
		{"192.168.1.1", false},
		{"100.64.0.1", false}, // CGNAT
		{"169.254.169.254", false}, // cloud metadata
		{"::1", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"::ffff:127.0.0.1", false}, // v4-mapped loopback
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test ip %q", c.ip)
		}
		if got := p.Allowed(ip); got != c.want {
			t.Errorf("Allowed(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestTargetPolicyAllowOverride(t *testing.T) {
	p, err := newTargetPolicy("192.168.0.0/16, 10.10.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	allow := []string{"192.168.1.5", "10.10.1.1"}
	for _, s := range allow {
		if !p.Allowed(net.ParseIP(s)) {
			t.Errorf("Allowed(%s) = false, want true (allow-cidr override)", s)
		}
	}
	// Other private ranges still denied.
	if p.Allowed(net.ParseIP("172.16.0.1")) {
		t.Error("172.16.0.1 should still be denied (not in allow-cidr)")
	}
}

func TestResolveAndCheckLiteral(t *testing.T) {
	p, _ := newTargetPolicy("")
	ips, port, err := p.resolveAndCheck("8.8.8.8:443")
	if err != nil {
		t.Fatal(err)
	}
	if port != "443" {
		t.Fatalf("port = %q, want 443", port)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("ips = %v, want [8.8.8.8]", ips)
	}
}

func TestResolveAndCheckDeniedLiteral(t *testing.T) {
	p, _ := newTargetPolicy("")
	if _, _, err := p.resolveAndCheck("127.0.0.1:22"); err == nil {
		t.Error("expected loopback to be denied, got nil error")
	}
	if _, _, err := p.resolveAndCheck("169.254.169.254:80"); err == nil {
		t.Error("expected cloud metadata IP to be denied")
	}
}

func TestNewTargetPolicyBadCIDR(t *testing.T) {
	if _, err := newTargetPolicy("not-a-cidr"); err == nil {
		t.Error("expected error on bogus CIDR")
	}
}
