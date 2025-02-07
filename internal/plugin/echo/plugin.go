package echo

import (
	"github.com/miekg/dns"
	"strings"
)

type Plugin struct{}

func (p *Plugin) Reply(m *dns.Msg) []byte {
	if m == nil {
		return nil
	}
	if len(m.Question) == 0 {
		return nil
	}

	question := m.Question[0]
	labels := strings.Split(question.Name, ".")
	if strings.ToLower(labels[0]) != p.Name() {
		return nil
	}

	b, err := m.Pack()
	if err != nil {
		// todo log

		return nil
	}

	return b
}

func (p *Plugin) Description() string {
	return "This plugin reply the exact same bytes it receives."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost echo.foo.com`"
}

func (p *Plugin) Name() string {
	return "echo"
}
