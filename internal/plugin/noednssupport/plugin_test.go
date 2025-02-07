package noednssupport

import (
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("no-edns-support.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, true)

		p := new(Plugin)
		b := p.Reply(m)
		require.NotNil(t, b)
		require.Equal(t, b, plugin.DropPacket)
	})

	t.Run("unhappy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("no-edns-support.foo.com"), dns.TypeA)
		m.Id = 12345

		p := new(Plugin)
		b := p.Reply(m)
		require.Nil(t, b)
	})
}
