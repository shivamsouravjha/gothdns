package emptyresponse

import (
    "github.com/miekg/dns"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "go.uber.org/zap"
    "testing"
)

func TestPlugin_Reply(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("emptyresponse.foo.com"), dns.TypeA)

		p := NewPlugin(zap.NewNop())
		b := p.Reply(m)

		require.NotNil(t, b)
		assert.ElementsMatch(t, []byte(""), b)
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
func TestPlugin_Reply_InvalidQuestionName(t *testing.T) {
    m := new(dns.Msg)
    m.SetQuestion(dns.Fqdn("invalid.foo.com"), dns.TypeA)

    p := NewPlugin(zap.NewNop())
    b := p.Reply(m)

    require.Nil(t, b)
}


// Test generated using Keploy
func TestPlugin_Description(t *testing.T) {
    p := NewPlugin(zap.NewNop())
    desc := p.Description()

    expected := "This plugin reply an empty message."
    require.Equal(t, expected, desc)
}


// Test generated using Keploy
func TestPlugin_Examples(t *testing.T) {
    p := NewPlugin(zap.NewNop())
    examples := p.Examples()

    expected := "`dig @localhost emptyresponse.foo.com`"
    require.Equal(t, expected, examples)
}

