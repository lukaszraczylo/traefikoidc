package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/lukaszraczylo/traefikoidc"
)

func main() {
	configPath := flag.String("config", "/etc/oidcgate/config.yaml", "Path to YAML config file")
	flag.Parse()

	cfg, err := Load(*configPath)
	if err != nil {
		log.Fatalf("oidcgate: load config: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	success := newSuccessHandler()
	middleware, err := traefikoidc.NewWithContext(ctx, &cfg.OIDC, success, "oidcgate")
	if err != nil {
		cancel()
		log.Fatalf("oidcgate: build middleware: %v", err)
	}

	mux := buildMux(cfg, middleware, middleware)
	srv := buildServer(cfg, mux)

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs
		log.Println("oidcgate: shutdown signal received")
		if err := shutdown(srv); err != nil {
			log.Printf("oidcgate: shutdown error: %v", err)
		}
		cancel()
	}()

	log.Printf("oidcgate: listening on %s", cfg.Listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("oidcgate: serve: %v", err)
	}
	log.Println("oidcgate: stopped")
}

