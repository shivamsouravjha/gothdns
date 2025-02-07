package internal

import (
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/echo"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/ednsformerr"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/emptyresponse"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/headeronly"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/headerquestion"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/noednssupport"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/nullbytes"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/soawrongsection"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/staticip"
	"github.com/blanchonvincent/go-PolarDNS/internal/plugin/wrongid"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

type RequestHandler struct {
	logger  *zap.Logger
	plugins []Plugin
}

func NewRequestHandler(logger *zap.Logger) *RequestHandler {
	return &RequestHandler{
		logger: logger,
		plugins: []Plugin{
			new(echo.Plugin),
			ednsformerr.NewPlugin(logger),
			new(emptyresponse.Plugin),
			headeronly.NewPlugin(logger),
			new(headerquestion.Plugin),
			new(noednssupport.Plugin),
			new(nullbytes.Plugin),
			soawrongsection.NewPlugin(logger),
			staticip.NewPlugin(logger),
			new(wrongid.Plugin),
		},
	}
}

func (h *RequestHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeFormatError)

		w.WriteMsg(m)
		return
	}

	question := r.Question[0]
	for _, plugin := range h.plugins {
		h.logger.Debug(
			"next plugin",
			zap.String("plugin", plugin.Name()),
			zap.String("qname", question.Name),
			zap.Uint16("qtype", question.Qtype),
		)

		if b := plugin.Reply(r); b != nil {
			h.logger.Debug(
				"plugin got a reply",
				zap.String("plugin", plugin.Name()),
				zap.String("qname", question.Name),
				zap.Uint16("qtype", question.Qtype),
			)

			w.Write(b)

			return
		}
	}
	h.logger.Debug(
		"no plugin found suitable to the query",
		zap.String("qname", question.Name),
		zap.Uint16("qtype", question.Qtype),
	)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeRefused

	w.WriteMsg(m)
}

func (h *RequestHandler) Plugins() []Plugin {
	return h.plugins
}
