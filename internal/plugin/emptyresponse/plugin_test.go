package emptyresponse

import (
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("empty-response.foo.com"), dns.TypeA)

		p := new(Plugin)
		b := p.Reply(m)

		require.NotNil(t, b)
		assert.ElementsMatch(t, []byte(""), b)
	})
}
