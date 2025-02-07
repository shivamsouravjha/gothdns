package emptyresponse

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

	return []byte("")
}

func (p *Plugin) Description() string {
	return "This plugin reply an empty message."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost empty-response.foo.com`"
}

func (p *Plugin) Name() string {
	return "empty-response"
}
