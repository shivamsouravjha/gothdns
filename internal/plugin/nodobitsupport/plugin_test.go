package nodobitsupport

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, false)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)
		require.NotNil(t, b)

		r := new(dns.Msg)
		err := r.Unpack(b)
		require.NoError(t, err)

		require.Equal(t, dns.RcodeNameError, r.Rcode)
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
			m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeTXT)
			m.Id = 12345
			m.SetEdns0(1232, false)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)
			require.Nil(t, b)
		})

		t.Run("DO bit to 1", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
			m.Id = 12345
			m.SetEdns0(1232, true)

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

		t.Run("no EDNS", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
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
	m.SetQuestion(dns.Fqdn("invalid-label.foo.com"), dns.TypeA)
	m.Id = 12345
	m.SetEdns0(1232, false)

	p := NewPlugin(zap.NewNop())
	b := p.Reply(m)
	require.Nil(t, b)
}

// Test generated using Keploy
func TestPlugin_Description_ReturnsCorrectDescription(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	description := p.Description()
	expected := "This plugin discard any packet that comes with EDNS0 DO bit to zero. Packet with DO to 1 will give a proper IP.\nSupport for A record only."
	assert.Equal(t, expected, description)
}

// Test generated using Keploy
func TestPlugin_DNSViolation_ReturnsCorrectDetails(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	violation := p.DNSViolation()
	assert.Equal(t, "DVE-2018-0001", violation.Identifier)
	assert.Equal(t, "https://github.com/dns-violations/dns-violations/blob/master/2018/DVE-2018-0001.md", violation.Link)
}
