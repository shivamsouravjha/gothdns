package plugin

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// Test generated using Keploy
func TestReplyWithDefaultARecord_ValidInput(t *testing.T) {
	// Set up DefaultIp if not already set
	if DefaultIp == nil {
		DefaultIp = net.ParseIP("192.0.2.1")
	}

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)
	result, err := ReplyWithDefaultARecord(msg)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if result == nil {
		t.Fatalf("Expected non-nil result")
	}
	response := new(dns.Msg)
	err = response.Unpack(result)
	if err != nil {
		t.Fatalf("Failed to unpack result: %v", err)
	}
	if len(response.Answer) != 1 {
		t.Fatalf("Expected 1 answer, got %d", len(response.Answer))
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("Expected A record, got %T", response.Answer[0])
	}
	expectedIp := DefaultIp.String()
	if aRecord.A.String() != expectedIp {
		t.Errorf("Expected IP %v, got %v", expectedIp, aRecord.A.String())
	}
}
