package emptyresponse

import (
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
	if len(m.Question) != 1 {
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
	return "`dig @localhost emptyresponse.foo.com`"
}

func (p *Plugin) Name() string {
	return "emptyresponse"
}
