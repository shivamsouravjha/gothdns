package soawrongsection

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("soa-wrong-section.foo.com"), dns.TypeSOA)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)

		r := new(dns.Msg)
		require.NoError(t, r.Unpack(b))

		require.NotNil(t, r)
		assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
		require.Equal(t, 0, len(r.Answer), r.String())
		require.Equal(t, 1, len(r.Ns), r.String())
		require.Equal(t, `soa-wrong-section.foo.com.	60	IN	SOA	ns.foo.com. hostmaster.foo.com. 20240207 3600 3600 3600 3600`, r.Ns[0].String(), r.String())
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
			m.SetQuestion(dns.Fqdn("soa-wrong-section.foo.com"), dns.TypeA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)
			require.Nil(t, b)
		})
	})
}
