package outbound

import "net"

// Dialer abstracts how the server connects to target addresses.
// When nil or unset, the server dials directly via net.DialTimeout.
type Dialer interface {
	DialTarget(target string) (net.Conn, error)
}
