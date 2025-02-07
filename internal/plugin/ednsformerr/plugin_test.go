package ednsformerr

import (
	"fmt"
	"github.com/blanchonvincent/go-PolarDNS/binary"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("edns-formerr.foo.com"), dns.TypeA)
		m.Id = 12345
		m.SetEdns0(1232, true)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)
		require.NotNil(t, b)
		assert.Equal(t,
			"["+
				binary.Uint16(m.Id)+" "+
				"10000000 "+ // first bit is QR
				"00000001 "+ // RA + RCODE
				"00000000 00000000 "+ // QDCOUNT
				"00000000 00000000 "+ // ANCOUNT
				"00000000 00000000 "+ // NSCOUNT
				"00000000 00000000"+ // ARCOUNT
				"]",
			fmt.Sprintf("%.8b", b),
		)
	})

	t.Run("unhappy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("edns-formerr.foo.com"), dns.TypeA)
		m.Id = 12345

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)
		require.Nil(t, b)
	})
}
