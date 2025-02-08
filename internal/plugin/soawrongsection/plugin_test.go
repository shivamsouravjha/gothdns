package soawrongsection

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
		m.SetQuestion(dns.Fqdn("soawrongsection.foo.com"), dns.TypeSOA)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)

		r := new(dns.Msg)
		require.NoError(t, r.Unpack(b))

		require.NotNil(t, r)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
		require.Equal(t, 0, len(r.Answer), r.String())
		require.Equal(t, 1, len(r.Ns), r.String())
		require.Equal(t, `soawrongsection.foo.com.	60	IN	SOA	ns.foo.com. hostmaster.foo.com. 20240207 3600 3600 3600 3600`, r.Ns[0].String(), r.String())
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

		t.Run("not type SOA", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("soawrongsection.foo.com"), dns.TypeA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)
			require.Nil(t, b)
		})
	})
}

// Test generated using Keploy
func TestPlugin_Reply_FirstLabelMismatch_ReturnsNil(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("wronglabel.foo.com"), dns.TypeSOA)

	p := NewPlugin(zap.NewNop())
	b := p.Reply(m)

	require.Nil(t, b)
}

// Test generated using Keploy
func TestPlugin_Description_ReturnsCorrectString(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	description := p.Description()
	expected := "This plugin reply to SOA query by setting up the SOA in AUTHORITY section rather than ANSWER.\nSupport for SOA record only."
	require.Equal(t, expected, description)
}

// Test generated using Keploy
func TestPlugin_Examples_ReturnsCorrectString(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	examples := p.Examples()
	expected := "`dig @localhost soawrongsection.foo.com`"
	require.Equal(t, expected, examples)
}

// Test generated using Keploy
func TestPlugin_DNSViolation_ReturnsCorrectViolation(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	violation := p.DNSViolation()
	expected := plugin.Violation{
		Identifier: "DVE-2020-0002",
		Link:       "https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0002.md",
	}
	require.Equal(t, expected, violation)
}
