package staticip

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
		t.Run("default IP", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("staticip.foo.com"), dns.TypeA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)

			r := new(dns.Msg)
			require.NoError(t, r.Unpack(b))

			require.NotNil(t, r)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
			require.Equal(t, 1, len(r.Answer), r.String())
			assert.Equal(t, plugin.DefaultIp.String(), r.Answer[0].(*dns.A).A.String(), r.String())
		})

		t.Run("chosen IP", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("staticip.1.2.3.4.foo.com"), dns.TypeA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)

			r := new(dns.Msg)
			require.NoError(t, r.Unpack(b))

			require.NotNil(t, r)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
			require.Equal(t, 1, len(r.Answer), r.String())
			assert.Equal(t, "1.2.3.4", r.Answer[0].(*dns.A).A.String(), r.String())
		})

		t.Run("wrong IP format", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("staticip.1.2.3.bar.foo.com"), dns.TypeA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)

			r := new(dns.Msg)
			require.NoError(t, r.Unpack(b))

			require.NotNil(t, r)
			assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
			require.Equal(t, 1, len(r.Answer), r.String())
			assert.Equal(t, "127.0.0.1", r.Answer[0].(*dns.A).A.String(), r.String())
		})
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

		t.Run("wrong type", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("staticip.foo.com"), dns.TypeAAAA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)

			require.Nil(t, b)
		})

		t.Run("wrong name", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("staticips.foo.com"), dns.TypeA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)

			require.Nil(t, b)
		})
	})
}

// Test generated using Keploy
func TestPlugin_Description(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	description := p.Description()
	expected := "This plugin allow you to get returned a static IP (by default `127.0.0.1`) or define your own from the query.\nOnly support A record for now."
	assert.Equal(t, expected, description)
}

// Test generated using Keploy
func TestPlugin_Examples(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	examples := p.Examples()
	expected := "`dig @localhost staticip.foo.com` or `dig @localhost staticip.1.2.3.4.foo.com` to get `1.2.3.4` back in the ANSWER section."
	assert.Equal(t, expected, examples)
}
