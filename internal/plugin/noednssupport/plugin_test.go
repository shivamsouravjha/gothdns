package noednssupport

import (
	"testing"

	"github.com/learn-dns-security-com/gothdns/internal/plugin"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("noednssupport.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, true)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)
		require.NotNil(t, b)
		require.Equal(t, b, plugin.DropPacket)
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
			m.SetQuestion(dns.Fqdn("noednssupport.foo.com"), dns.TypeTXT)
			m.Id = 12345

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)
			require.Nil(t, b)
		})

		t.Run("no EDNS", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("noednssupport.foo.com"), dns.TypeA)
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
func TestPlugin_Reply_FirstLabelMismatch_ReturnsNil(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("invalid.foo.com"), dns.TypeA)
	m.Id = 12345

	p := NewPlugin(zap.NewNop())
	b := p.Reply(m)
	require.Nil(t, b)
}

// Test generated using Keploy
func TestPlugin_Description_ReturnsCorrectString(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	expected := "This plugin discard any packet that comes with OPT record.\nSupport for A record only."
	actual := p.Description()
	require.Equal(t, expected, actual)
}

// Test generated using Keploy
func TestPlugin_Examples_ReturnsCorrectString(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	expected := "`dig @localhost noednssupport.foo.com +edns`"
	actual := p.Examples()
	require.Equal(t, expected, actual)
}

// Test generated using Keploy
func TestPlugin_DNSViolation_ReturnsCorrectDetails(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	expected := plugin.Violation{
		Identifier: "DVE-2020-0004",
		Link:       "https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0004.md",
	}
	actual := p.DNSViolation()
	require.Equal(t, expected, actual)
}
