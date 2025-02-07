package wrongid

import (
	"fmt"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Run("A record", func(t *testing.T) {
			for _, id := range []uint16{1, 123, 65535} {
				t.Run(fmt.Sprint(id), func(t *testing.T) {
					m := new(dns.Msg)
					m.SetQuestion(dns.Fqdn("wrong-id.foo.com"), dns.TypeA)
					m.Id = id

					p := new(Plugin)
					b := p.Reply(m)
					require.NotNil(t, b)

					r := new(dns.Msg)
					require.NoError(t, r.Unpack(b))

					assert.Equal(t, dns.RcodeSuccess, r.Rcode, r.String())
					assert.NotEqual(t, r.Id, m.Id, r.String())
					require.Equal(t, 1, len(r.Answer), r.String())
					assert.Equal(t, plugin.DefaultIp.String(), r.Answer[0].(*dns.A).A.String(), r.String())
				})
			}
		})
	})
}
