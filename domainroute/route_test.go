package domainroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDialExactDomainAndNoFallback(t *testing.T) {
	dns, err := NewDNS(netip.MustParsePrefix("198.18.0.0/29"), 4)
	if err != nil {
		t.Fatal(err)
	}
	virtual := func(domain string) netip.AddrPort {
		t.Helper()
		addr, err := dns.assign(dnsmessage.MustNewName(domain))
		if err != nil {
			t.Fatal(err)
		}
		return netip.AddrPortFrom(addr, 443)
	}
	real := netip.MustParseAddr("203.0.113.7")
	lookup := func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{real}, nil }
	directErr := errors.New("direct selected")
	tunnelErr := errors.New("tunnel down")
	dial := func(result error) DialIPv4 {
		return func(_ context.Context, network string, dst netip.AddrPort) (net.Conn, error) {
			if network != "tcp" || dst != netip.AddrPortFrom(real, 443) {
				t.Fatalf("unexpected network or destination: %s %s", network, dst)
			}
			return nil, result
		}
	}
	exact, subdomain := virtual("example.com."), virtual("api.example.com.")
	for _, tc := range []struct {
		mode     Mode
		prefix   []netip.Prefix
		app      bool
		dst      netip.AddrPort
		expected error
	}{
		{IncludeOnly, nil, true, exact, tunnelErr},
		{IncludeOnly, nil, true, subdomain, directErr},
		{IncludeOnly, nil, false, exact, directErr},
		{IncludeOnly, []netip.Prefix{netip.PrefixFrom(real, 32)}, true, subdomain, tunnelErr},
		{Exclude, nil, false, exact, directErr},
		{Exclude, nil, false, subdomain, tunnelErr},
		{Exclude, nil, true, subdomain, directErr},
	} {
		policy := Policy{Mode: tc.mode, AppRulesConfigured: true, Domains: []string{"example.com"}, Prefixes: tc.prefix}
		_, err := dns.Dial(context.Background(), policy, tc.app, "tcp", tc.dst, lookup, dial(directErr), dial(tunnelErr))
		if !errors.Is(err, tc.expected) {
			t.Fatalf("routing %+v: got %v, want %v", tc, err, tc.expected)
		}
	}

	unknown := netip.MustParseAddrPort("198.18.0.6:443")
	_, err = dns.Dial(context.Background(), Policy{Mode: Exclude}, false, "tcp", unknown, lookup, dial(directErr), dial(tunnelErr))
	if !errors.Is(err, ErrUnknownVirtualIP) {
		t.Fatalf("unknown virtual destination was not rejected: %v", err)
	}
}
