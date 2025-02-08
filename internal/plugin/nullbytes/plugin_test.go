package nullbytes

import (
	"fmt"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		t.Run("1 len", func(t *testing.T) {
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
				t.Run(fmt.Sprintf("qt %d", qt), func(t *testing.T) {
					m := new(dns.Msg)
					m.SetQuestion(dns.Fqdn("nullbytes.foo.com"), qt)

					p := NewPlugin(zap.NewNop())
					b := p.Reply(m)

					require.NotNil(t, b)
					assert.Len(t, b, 1)
					assert.Equal(t, "[0]", fmt.Sprint(b))
				})
			}
		})

		t.Run("8 len", func(t *testing.T) {
			for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeTXT} {
				t.Run(fmt.Sprintf("qt %d", qt), func(t *testing.T) {
					m := new(dns.Msg)
					m.SetQuestion(dns.Fqdn("nullbytes.8.foo.com"), dns.TypeA)

					p := NewPlugin(zap.NewNop())
					b := p.Reply(m)

					require.NotNil(t, b)
					assert.Len(t, b, 8)
					assert.Equal(t, "[00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000]", fmt.Sprintf("%.8b", b))
				})
			}
		})

		t.Run("mix subdomain numbers and letters", func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("nullbytes.8d.foo.com"), dns.TypeA)

			p := NewPlugin(zap.NewNop())
			b := p.Reply(m)

			require.NotNil(t, b)
			assert.Len(t, b, 1)
			assert.Equal(t, "[00000000]", fmt.Sprintf("%.8b", b))
		})
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

// Test generated using Keploy
func TestPlugin_Reply_InvalidQuestionName_ReturnsNil(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("invalid.foo.com"), dns.TypeA)

	p := NewPlugin(zap.NewNop())
	b := p.Reply(m)

	require.Nil(t, b)
}

// Test generated using Keploy
func TestPlugin_Description_ReturnsCorrectString(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	desc := p.Description()

	assert.Equal(t, "This plugin responds with only NULL bytes.", desc)
}

// Test generated using Keploy
func TestPlugin_Examples_ReturnsCorrectString(t *testing.T) {
	p := NewPlugin(zap.NewNop())
	examples := p.Examples()

	assert.Equal(t, "`dig @localhost nullbytes.foo.com` with 1 NULL byte or `dig @localhost nullbytes.20.foo.com` for 20 NULL bytes", examples)
}
