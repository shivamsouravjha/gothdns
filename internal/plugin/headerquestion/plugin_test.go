package headerquestion

import (
	"fmt"
	"github.com/learn-dns-security-com/gothdns/binary"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
			t.Run(fmt.Sprintf("qt %d", qt), func(t *testing.T) {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn("header-question.foo.com"), qt)
				m.Id = 12345

				p := NewPlugin(zap.NewNop())
				b := p.Reply(m)
				require.NotNil(t, b)

				q := m.Question[0]

				assert.Equal(t,
					"["+
						binary.Uint16(m.Id)+" "+
						"10000001 "+ // first bit is QR and last is RD
						"00000000 "+ // RA + RCODE
						"00000000 00000001 "+ // QDCOUNT
						"00000000 00000001 "+ // ANCOUNT
						"00000000 00000000 "+ // NSCOUNT
						"00000000 00000000 "+ // ARCOUNT
						binary.Qname(q.Name)+" "+
						binary.Uint16(q.Qtype)+" "+
						binary.Uint16(q.Qclass)+
						"]",
					fmt.Sprintf("%.8b", b),
				)
			})
		}
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
	})
}
