package domainroute

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestVirtualDNSSeparatesSharedAddresses(t *testing.T) {
	dns, err := NewDNS(netip.MustParsePrefix("198.18.0.0/29"), 2)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(_ context.Context, domain string) ([]netip.Addr, error) {
		if domain == "missing.example" {
			return nil, &net.DNSError{IsNotFound: true}
		}
		return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
	}
	query := func(domain string) (dnsmessage.Message, error) {
		t.Helper()
		name, err := dnsmessage.NewName(domain)
		if err != nil {
			t.Fatal(err)
		}
		msg := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: 42, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		}
		wire, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}
		wire, err = dns.AnswerA(context.Background(), wire, lookup)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		err = msg.Unpack(wire)
		return msg, err
	}
	answerIP := func(domain string) netip.Addr {
		t.Helper()
		answer, err := query(domain)
		if err != nil || answer.ID != 42 || !answer.Response || len(answer.Answers) != 1 {
			t.Fatalf("unexpected DNS answer for %s: %+v, %v", domain, answer, err)
		}
		return netip.AddrFrom4(answer.Answers[0].Body.(*dnsmessage.AResource).A)
	}
	first := answerIP("Example.com.")
	second := answerIP("api.example.com.")
	if first == second || first != answerIP("example.com.") {
		t.Fatalf("unexpected mapping: %s, %s", first, second)
	}
	if domain, ok := dns.Domain(second); !ok || domain != "api.example.com" {
		t.Fatalf("lookup: %q, %v", domain, ok)
	}
	if _, err := query("other.example."); !errors.Is(err, ErrAddressPoolFull) {
		t.Fatalf("expected exhausted pool, got %v", err)
	}
	if response, err := query("missing.example."); err != nil || response.RCode != dnsmessage.RCodeNameError || len(response.Answers) != 0 {
		t.Fatalf("unexpected missing-name response: %+v, %v", response, err)
	}
}
