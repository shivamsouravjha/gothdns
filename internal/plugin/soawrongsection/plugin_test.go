package soawrongsection

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("soa-wrong-section.foo.com"), dns.TypeSOA)

		p := new(Plugin)
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
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("soa-wrong-section.foo.com"), dns.TypeA)

		p := new(Plugin)
		b := p.Reply(m)
		require.Nil(t, b)
	})
}
