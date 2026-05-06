package server

import (
	"fmt"
	"net"
	"strings"
)

// targetPolicy decides whether a resolved IP may be dialed by the proxy.
// Default-deny against the standard private/bogon set; the operator can
// punch holes in it via --allow-cidr (e.g. allow a specific RFC1918 range
// to reach an internal service).
type targetPolicy struct {
	deny  []*net.IPNet
	allow []*net.IPNet
}

// defaultDenyCIDRs covers loopback, RFC1918, CGNAT, link-local, multicast,
// reserved, IPv6 ULA / link-local — the standard "do not let a public-
// Internet proxy reach this" set. IPv4-mapped IPv6 forms (::ffff:127.0.0.1
// etc.) are normalized to IPv4 by Allowed via IP.To4 before the rules are
// consulted, so the v4 entries below cover them too.
var defaultDenyCIDRs = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

// newTargetPolicy returns a policy with the default deny list and the
// supplied comma-separated allow list. allowCIDR "" disables overrides.
func newTargetPolicy(allowCIDR string) (*targetPolicy, error) {
	p := &targetPolicy{}
	for _, c := range defaultDenyCIDRs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("internal: bad default cidr %q: %w", c, err)
		}
		p.deny = append(p.deny, n)
	}
	for _, c := range strings.Split(allowCIDR, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("bad allow cidr %q: %w", c, err)
		}
		p.allow = append(p.allow, n)
	}
	return p, nil
}

// Allowed reports whether ip may be dialed. Allow entries override deny.
// A nil policy allows everything (used in tests / disabled mode).
//
// IPv4-mapped IPv6 addresses (::ffff:127.0.0.1) are normalized to plain
// IPv4 first so a v6-encoded loopback can't slip past the v4 deny list.
func (p *targetPolicy) Allowed(ip net.IP) bool {
	if p == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range p.allow {
		if n.Contains(ip) {
			return true
		}
	}
	for _, n := range p.deny {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// resolveAndCheck splits target into host:port, resolves the host (or parses
// an IP literal), filters the result through the policy, and returns the
// allowed IPs paired with the port string. The caller is expected to dial
// these IPs directly rather than re-resolving via the hostname — that is
// what closes the DNS-rebinding window where the second resolution would
// pick a previously-filtered-out IP.
func (p *targetPolicy) resolveAndCheck(target string) ([]net.IP, string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, "", err
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ips, err = net.LookupIP(host)
		if err != nil {
			return nil, "", err
		}
	}

	allowed := ips[:0]
	for _, ip := range ips {
		if p.Allowed(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, "", fmt.Errorf("policy: all resolved IPs for %s denied", target)
	}
	return allowed, port, nil
}
