package nodobitsupport

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, false)

		p := new(Plugin)
		b := p.Reply(m)
		require.NotNil(t, b)

		r := new(dns.Msg)
		err := r.Unpack(b)
		require.NoError(t, err)

		require.Equal(t, dns.RcodeNameError, r.Rcode)
	})

	t.Run("unhappy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("no-dobit-support.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, true)

		p := new(Plugin)
		b := p.Reply(m)
		require.Nil(t, b)
	})
}
