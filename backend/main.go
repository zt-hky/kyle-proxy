package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"kyle-proxy/internal/api"
	"kyle-proxy/internal/config"
	"kyle-proxy/internal/proxy"
	"kyle-proxy/internal/vpn"
)

//go:embed static
var embeddedStatic embed.FS

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("🚀 Kyle VPN Proxy starting…")

	// ── Config ───────────────────────────────────────────────────────────────
	cfgPath := envOr("CONFIG_PATH", "/data/config.json")
	cfgMgr := config.NewManager(cfgPath)
	cfg := cfgMgr.Load()

	// ── VPN manager ──────────────────────────────────────────────────────────
	vpnMgr := vpn.NewManager()

	// ── Proxy manager ────────────────────────────────────────────────────────
	proxyMgr := proxy.NewManager(proxy.Config{
		HTTPPort:   cfg.Proxy.HTTPPort,
		Socks5Port: cfg.Proxy.Socks5Port,
	})

	if err := proxyMgr.Start(); err != nil {
		log.Printf("⚠️  v2ray failed to start: %v (proxy will be unavailable)", err)
	}

	// ── Static frontend ──────────────────────────────────────────────────────
	var staticFS fs.FS
	sub, err := fs.Sub(embeddedStatic, "static")
	if err == nil {
		// Check there's actually content in the embedded dir
		if f, err2 := sub.Open("index.html"); err2 == nil {
			f.Close()
			staticFS = sub
			log.Println("📦 Serving embedded Svelte frontend")
		} else {
			log.Println("⚠️  No embedded frontend found — run 'make build-frontend' first")
		}
	}

	// ── HTTP server ──────────────────────────────────────────────────────────
	addr := envOr("LISTEN_ADDR", ":8888")
	router := api.NewRouter(vpnMgr, proxyMgr, cfgMgr, staticFS)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("🌐 Management UI → http://0.0.0.0%s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down…")

	_ = vpnMgr.Disconnect()
	proxyMgr.Stop()

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)

	log.Println("Bye!")
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
