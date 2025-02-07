package headerquestion

import (
	"fmt"
	"github.com/blanchonvincent/go-PolarDNS/binary"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
			t.Run(fmt.Sprintf("qt %d", qt), func(t *testing.T) {
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn("header-question.foo.com"), qt)
				m.Id = 12345

				p := new(Plugin)
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
}
