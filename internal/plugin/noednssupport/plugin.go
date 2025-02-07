package noednssupport

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"strings"
)

type Plugin struct {
	logger *zap.Logger
}

func NewPlugin(logger *zap.Logger) *Plugin {
	p := new(Plugin)
	p.logger = logger.With(zap.String("plugin", p.Name()))

	return p
}

func (p *Plugin) Reply(m *dns.Msg) []byte {
	if m == nil {
		return nil
	}
	if len(m.Question) == 0 {
		return nil
	}

	question := m.Question[0]
	if question.Qtype != dns.TypeA {
		return nil
	}

	labels := strings.Split(question.Name, ".")
	if strings.ToLower(labels[0]) != p.Name() {
		return nil
	}

	if opt := m.IsEdns0(); opt != nil {
		return plugin.DropPacket
	}

	b, err := plugin.ReplyWithDefaultARecord(m)
	if err != nil {
		p.logger.Error("failed create response", zap.Error(err))

		return nil
	}
	return b
}

func (p *Plugin) Description() string {
	return "This plugin discard any packet that comes with OPT record.\nSupport for A record only."
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
