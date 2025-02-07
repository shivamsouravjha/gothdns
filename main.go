package main

import (
	"context"
	"github.com/blanchonvincent/go-PolarDNS/internal"
	"github.com/miekg/dns"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
)

func main() {
	logger, err := zap.NewDevelopment()
	if err != nil {
		panic("error initializing logger: " + err.Error())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger.Info("starting OS signals listener...")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		cancel()
	}()

	Run(ctx, logger)
}

func Run(ctx context.Context, logger *zap.Logger) {
	handler := internal.NewRequestHandler(logger)

	udp := &dns.Server{
		Addr:    ":53",
		Net:     "udp",
		Handler: handler,
	}
	go func() {
		logger.Info("starting UDP listener on port 53...")

		udp.ListenAndServe()
	}()
	defer udp.Shutdown()

	tcp := &dns.Server{
		Addr:    ":53",
		Net:     "tcp",
		Handler: handler,
	}
	go func() {
		logger.Info("starting TCP listener on port 53...")

		tcp.ListenAndServe()
	}()
	defer tcp.Shutdown()

	<-ctx.Done()
}
