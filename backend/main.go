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

type telegramConfig struct {
	token   string
	ownerID int64
	enabled bool
	reason  string
}

func telegramConfigFromEnv() telegramConfig {
	token, ownerText := os.Getenv("TELEGRAM_BOT_TOKEN"), os.Getenv("TELEGRAM_OWNER_ID")
	if token == "" && ownerText == "" {
		return telegramConfig{reason: "Telegram bot disabled"}
	}
	if token == "" || ownerText == "" {
		return telegramConfig{reason: "Telegram bot disabled: token and owner ID are both required"}
	}
	ownerID, err := strconv.ParseInt(ownerText, 10, 64)
	if err != nil || ownerID <= 0 {
		return telegramConfig{reason: "Telegram bot disabled: invalid owner ID"}
	}
	return telegramConfig{token: token, ownerID: ownerID, enabled: true}
}

type telegramService interface {
	Start(context.Context)
	BeginShutdown()
	Flush(context.Context) error
}

var newTelegramService = func(token string, ownerID int64, accessPath string, controller *control.VPN) (telegramService, error) {
	return telegram.New(token, ownerID, accessPath, controller)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	run(ctx)
}

func run(ctx context.Context) {
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

	var botSvc telegramService
	botCfg := telegramConfigFromEnv()
	if !botCfg.enabled {
		log.Println(botCfg.reason)
	} else {
		var err error
		botSvc, err = newTelegramService(botCfg.token, botCfg.ownerID, envOr("TELEGRAM_ACCESS_PATH", "/data/telegram-access.json"), controller)
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
