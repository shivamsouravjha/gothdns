package echo

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("echo.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, true)

		p := new(Plugin)
		b := p.Reply(m)
		require.NotNil(t, b)

		bm, err := m.Pack()
		require.NoError(t, err)

		assert.Equal(t, bm, b)
	})
}
