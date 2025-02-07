package ednsformerr

import (
	"github.com/learn-dns-security-com/gothdns/internal/plugin"
	"github.com/learn-dns-security-com/gothdns/packet"
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"strings"
)

type Plugin struct {
	logger *zap.Logger
}

func NewPlugin(logger *zap.Logger) *Plugin {
	return &Plugin{
		logger: logger,
	}
}

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
		r := new(dns.Msg)
		r.Id = m.Id
		r.Response = true
		r.Rcode = dns.RcodeFormatError

		pp, err := packet.NewMessageParser(r)
		if err != nil {
			p.logger.Error("failed to parse message", zap.Error(err))
			return nil
		}

		b, err := pp.Header()
		if err != nil {
			p.logger.Error("failed to parse header", zap.Error(err))
			return nil
		}

		return b
	}

	return nil
}

func (p *Plugin) Description() string {
	return "This plugin reply FORMERR with QUESTION section."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost ednsformerr.foo.com +edns`"
}

func (p *Plugin) Name() string {
	return "edns-formerr"
}

func (p *Plugin) DNSViolation() plugin.Violation {
	return plugin.Violation{
		Identifier: "DVE-2020-0001",
		Link:       "https://github.com/dns-violations/dns-violations/blob/master/2020/DVE-2020-0001.md",
	}
}
