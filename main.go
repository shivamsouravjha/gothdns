package main

import (
	"context"
	"github.com/learn-dns-security-com/gothdns/internal"
	"github.com/learn-dns-security-com/gothdns/internal/config"
	"github.com/miekg/dns"
	"net"
	"os"
	"os/signal"
	"strconv"
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

	logger.Info("loading configuration...")
	cfg, err := config.Load()
	if err != nil {
		logger.Fatal("error loading configuration", zap.Error(err))
	}

	logger.Info("starting OS signals listener...")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		cancel()
	}()

	Run(ctx, logger, cfg)
}

func Run(ctx context.Context, logger *zap.Logger, cfg config.Environment) {
	logger.Info("loading plugins...")
	handler := internal.NewRequestHandler(logger)

	udp := &dns.Server{
		Addr:    net.JoinHostPort(cfg.Addr, strconv.Itoa(cfg.Port)),
		Net:     "udp",
		Handler: handler,
	}
	go func() {
		logger.Info("starting UDP listener on port 53...")

		udp.ListenAndServe()
	}()
	defer udp.Shutdown()

	tcp := &dns.Server{
		Addr:    net.JoinHostPort(cfg.Addr, strconv.Itoa(cfg.Port)),
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
