package nullbytes

import (
	"github.com/miekg/dns"
	"go.uber.org/zap"
	"strconv"
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

	repeat := 1
	if len(labels) > 1 {
		if num, err := strconv.Atoi(labels[1]); err == nil {
			repeat = num
		}
	}

	var b []byte
	for i := 0; i < repeat; i++ {
		b = append(b, []byte("\x00")...)
	}

	return b
}

func (p *Plugin) Description() string {
	return "This plugin responds with only NULL bytes."
}

func (p *Plugin) Examples() string {
	return "`dig @localhost null-bytes.foo.com` with 1 NULL byte or `dig @localhost null-bytes.20.foo.com` for 20 NULL bytes"
}

func (p *Plugin) Name() string {
	return "null-bytes"
}
