package noednssupport

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
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

	if opt := m.IsEdns0(); opt != nil {
		return plugin.DropPacket
	}

	return nil
}

func (p *Plugin) Description() string {
	return "This plugin discard any packet that comes with OPT record."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost no-edns-support.foo.com +edns`"
}

func (p *Plugin) Name() string {
	return "no-edns-support"
}

func (p *Plugin) DNSViolation() plugin.Violation {
	return plugin.Violation{
		Identifier: "DVE-2020-0004",
		Link:       "https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0004.md",
	}
}
