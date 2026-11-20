package domainroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

type Mode uint8

const (
	Exclude Mode = iota + 1
	IncludeOnly
)

type Path uint8

const (
	Direct Path = iota + 1
	Tunnel
)

var (
	ErrUnknownVirtualIP = errors.New("unknown virtual destination")
	ErrNoIPv4Address    = errors.New("destination has no usable IPv4 address")
	ErrPathUnavailable  = errors.New("selected connection path is unavailable")
)

type Policy struct {
	Mode               Mode
	AppRulesConfigured bool
	Domains            []string
	Prefixes           []netip.Prefix
}

type DialIPv4 func(context.Context, string, netip.AddrPort) (net.Conn, error)

// Dial routes a TCP or UDP connection to a literal or virtual destination.
// appSelected is supplied by the platform; the DNS mapping has no app identity.
func (d *DNS) Dial(ctx context.Context, policy Policy, appSelected bool, network string,
	destination netip.AddrPort, lookup LookupIPv4, direct, tunnel DialIPv4,
) (net.Conn, error) {
	if policy.Mode != Exclude && policy.Mode != IncludeOnly {
		return nil, errors.New("invalid domain routing mode")
	}
	if !destination.Addr().Is4() || destination.Port() == 0 {
		return nil, ErrNoIPv4Address
	}

	realIP := destination.Addr()
	domain := ""
	if d.pool.Contains(realIP) {
		var ok bool
		domain, ok = d.Domain(realIP)
		if !ok {
			return nil, ErrUnknownVirtualIP
		}
		addresses, err := lookup(ctx, domain)
		if err != nil {
			return nil, err
		}
		realIP = netip.Addr{}
		for _, address := range addresses {
			if address.Is4() && !d.pool.Contains(address) {
				realIP = address
				break
			}
		}
		if !realIP.IsValid() {
			return nil, ErrNoIPv4Address
		}
	}

	dial := direct
	if policy.path(appSelected, domain, realIP) == Tunnel {
		dial = tunnel
	}
	if dial == nil {
		return nil, ErrPathUnavailable
	}
	return dial(ctx, network, netip.AddrPortFrom(realIP, destination.Port()))
}

func (p Policy) path(appSelected bool, domain string, ip netip.Addr) Path {
	matches := false
	for _, rule := range p.Domains {
		if domain != "" && domain == strings.TrimSuffix(strings.ToLower(rule), ".") {
			matches = true
			break
		}
	}
	for _, prefix := range p.Prefixes {
		if prefix.Contains(ip) {
			matches = true
			break
		}
	}
	destinationsConfigured := len(p.Domains)+len(p.Prefixes) > 0

	if p.Mode == Exclude {
		if (p.AppRulesConfigured && appSelected) || matches {
			return Direct
		}
		return Tunnel
	}
	if (p.AppRulesConfigured || destinationsConfigured) &&
		(!p.AppRulesConfigured || appSelected) && (!destinationsConfigured || matches) {
		return Tunnel
	}
	return Direct
}
