package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"globalprotect-manager/internal/api"
	"globalprotect-manager/internal/auth"
	"globalprotect-manager/internal/config"
	"globalprotect-manager/internal/control"
	"globalprotect-manager/internal/telegram"
	"globalprotect-manager/internal/vpn"
)

//go:embed static
var embeddedStatic embed.FS

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("GlobalProtect Manager starting")
	cfgMgr := config.NewManager(envOr("CONFIG_PATH", "/data/config.json"))
	cfgMgr.Load()
	vpnMgr := vpn.NewManager()
	controller := control.NewVPN(vpnMgr, cfgMgr)
	ghAuth := auth.NewGitHubAuth()
	if ghAuth.Enabled {
		log.Println("GitHub OAuth2 authentication enabled")
	} else {
		log.Println("GitHub auth not configured — management UI is unprotected")
	}

	var botSvc *telegram.Service
	token, ownerText := os.Getenv("TELEGRAM_BOT_TOKEN"), os.Getenv("TELEGRAM_OWNER_ID")
	if token == "" && ownerText == "" {
		log.Println("Telegram bot disabled")
	} else if token == "" || ownerText == "" {
		log.Println("Telegram bot disabled: token and owner ID are both required")
	} else if ownerID, err := strconv.ParseInt(ownerText, 10, 64); err != nil || ownerID <= 0 {
		log.Printf("Telegram bot disabled: invalid owner ID")
	} else {
		botSvc, err = telegram.New(token, ownerID, envOr("TELEGRAM_ACCESS_PATH", "/data/telegram-access.json"), controller)
		if err != nil {
			log.Printf("Telegram bot disabled: %v", err)
		}
	}

	var staticFS fs.FS
	if sub, err := fs.Sub(embeddedStatic, "static"); err == nil {
		if f, e := sub.Open("index.html"); e == nil {
			f.Close()
			staticFS = sub
			log.Println("Serving embedded Svelte frontend")
		}
	}
	router := api.NewRouter(controller, cfgMgr, ghAuth, staticFS)
	srv := &http.Server{Addr: envOr("LISTEN_ADDR", ":8888"), Handler: router}
	pollCtx, pollCancel := context.WithCancel(context.Background())
	defer pollCancel()
	if botSvc != nil {
		go botSvc.Start(pollCtx)
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	log.Println("Shutting down")
	if botSvc != nil {
		botSvc.BeginShutdown()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	_ = controller.Disconnect()
	if botSvc != nil {
		flushCtx, fc := context.WithTimeout(context.Background(), 5*time.Second)
		_ = botSvc.Flush(flushCtx)
		fc()
		pollCancel()
	}
	log.Println("Bye")
}
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
