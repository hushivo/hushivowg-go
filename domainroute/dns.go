// Package domainroute associates local DNS names with virtual IPv4 destinations.
package domainroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	ErrUnsupportedQuery = errors.New("expected a single IPv4 DNS question")
	ErrAddressPoolFull  = errors.New("virtual DNS address pool exhausted")
)

// DNS owns the virtual addresses for one tunnel session. A virtual address is
// never reassigned during that session, even after its DNS TTL expires.
type DNS struct {
	mu     sync.Mutex
	pool   netip.Prefix
	next   netip.Addr
	limit  int
	byName map[dnsmessage.Name]netip.Addr
	byIP   map[netip.Addr]string
}

// NewDNS takes a dedicated IPv4 prefix that the caller routes into its local
// connection handler. It must not overlap actual destination routes.
func NewDNS(pool netip.Prefix, limit int) (*DNS, error) {
	if !pool.Addr().Is4() || pool.Bits() < 1 || pool.Bits() > 30 || limit < 1 {
		return nil, errors.New("invalid virtual DNS address pool")
	}
	pool = pool.Masked()
	return &DNS{
		pool: pool, next: pool.Addr().Next(), limit: limit,
		byName: make(map[dnsmessage.Name]netip.Addr),
		byIP:   make(map[netip.Addr]string),
	}, nil
}

// Domain returns the exact normalized name assigned to a virtual destination.
func (d *DNS) Domain(ip netip.Addr) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	name, ok := d.byIP[ip]
	return name, ok
}

func (d *DNS) assign(name dnsmessage.Name) (netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ip, ok := d.byName[name]; ok {
		return ip, nil
	}
	if len(d.byIP) >= d.limit || !d.pool.Contains(d.next) || !d.pool.Contains(d.next.Next()) {
		return netip.Addr{}, ErrAddressPoolFull
	}
	ip := d.next
	d.next = ip.Next()
	d.byName[name] = ip
	d.byIP[ip] = strings.TrimSuffix(name.String(), ".")
	return ip, nil
}

// LookupIPv4 looks up the real address of a name using the caller's upstream
// DNS policy. An empty result means the name has no A records.
type LookupIPv4 func(ctx context.Context, name string) ([]netip.Addr, error)

// AnswerA builds a DNS answer for a single A question. Other questions must be
// handled separately by the caller. No virtual address is issued unless the
// upstream name resolves to at least one real IPv4 address.
func (d *DNS) AnswerA(ctx context.Context, wire []byte, lookup LookupIPv4) ([]byte, error) {
	var request dnsmessage.Message
	if err := request.Unpack(wire); err != nil {
		return nil, err
	}
	if request.Response || request.OpCode != 0 || len(request.Questions) != 1 ||
		request.Questions[0].Type != dnsmessage.TypeA || request.Questions[0].Class != dnsmessage.ClassINET {
		return nil, ErrUnsupportedQuery
	}
	question := request.Questions[0]
	name, err := dnsmessage.NewName(strings.ToLower(question.Name.String()))
	if err != nil {
		return nil, err
	}
	response := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: request.ID, Response: true, RecursionDesired: request.RecursionDesired, RecursionAvailable: true},
		Questions: request.Questions,
	}
	addresses, err := lookup(ctx, strings.TrimSuffix(name.String(), "."))
	if err != nil {
		var dnsErr *net.DNSError
		response.RCode = dnsmessage.RCodeServerFailure
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			response.RCode = dnsmessage.RCodeNameError
		}
		return response.Pack()
	}
	for _, address := range addresses {
		if !address.Is4() {
			continue
		}
		ip, err := d.assign(name)
		if err != nil {
			return nil, err
		}
		response.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 30},
			Body:   &dnsmessage.AResource{A: ip.As4()},
		}}
		break
	}
	return response.Pack()
}
