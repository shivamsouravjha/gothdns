package ednsformerr

import (
    "fmt"
    "github.com/learn-dns-security-com/gothdns/binary"
    "github.com/miekg/dns"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.uber.org/zap"
    "testing"
    "github.com/learn-dns-security-com/gothdns/internal/plugin"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("ednsformerr.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, true)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)
		require.NotNil(t, b)
		assert.Equal(t,
			"["+
				binary.Uint16(m.Id)+" "+
				"10000000 "+ // first bit is QR
				"00000001 "+ // RA + RCODE
				"00000000 00000000 "+ // QDCOUNT
				"00000000 00000000 "+ // ANCOUNT
				"00000000 00000000 "+ // NSCOUNT
				"00000000 00000000"+ // ARCOUNT
				"]",
			fmt.Sprintf("%.8b", b),
		)
	})

	t.Run("unhappy path", func(t *testing.T) {
		t.Run("nil message", func(t *testing.T) {
			p := NewPlugin(zap.NewNop())
			b := p.Reply(nil)
			require.Nil(t, b)
		})

		t.Run("0 questions", func(t *testing.T) {
			p := NewPlugin(zap.NewNop())
			b := p.Reply(new(dns.Msg))
			require.Nil(t, b)
		})

		t.Run("not type A", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("ednsformerr.foo.com"), dns.TypeTXT)
			m.Id = 12345
			m.SetEdns0(1232, true)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)
			require.Nil(t, b)
		})

		t.Run("no edns", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("ednsformerr.foo.com"), dns.TypeA)
			m.Id = 12345

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)
			require.NotNil(t, b)

			r := new(dns.Msg)
			err := r.Unpack(b)
			require.NoError(t, err)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
			require.Equal(t, 1, len(r.Answer), r.String())
			assert.Equal(t, "127.0.0.1", r.Answer[0].(*dns.A).A.String(), r.String())
		})
	})
}

// Test generated using Keploy
func TestPlugin_Description(t *testing.T) {
    p := NewPlugin(zap.NewNop())
    description := p.Description()
    expected := "This plugin reply FORMERR for any query with EDNS and a valid IP for query without EDNS.\nSupport for A record only."
    assert.Equal(t, expected, description)
}


// Test generated using Keploy
func TestPlugin_Examples(t *testing.T) {
    p := NewPlugin(zap.NewNop())
    examples := p.Examples()
    expected := "`dig @localhost ednsformerr.foo.com +edns`"
    assert.Equal(t, expected, examples)
}


// Test generated using Keploy
func TestPlugin_DNSViolation(t *testing.T) {
    p := NewPlugin(zap.NewNop())
    violation := p.DNSViolation()
    expected := plugin.Violation{
        Identifier: "DVE-2020-0001",
        Link:       "https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0001.md",
    }
    assert.Equal(t, expected, violation)
}

