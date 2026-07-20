package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"globalprotect-manager/internal/control"
)

func TestEnvOr(t *testing.T) {
	t.Setenv("PRESENT", "value")
	if got := envOr("PRESENT", "fallback"); got != "value" {
		t.Fatalf("envOr present = %q", got)
	}
	t.Setenv("MISSING", "")
	if got := envOr("MISSING", "fallback"); got != "fallback" {
		t.Fatalf("envOr fallback = %q", got)
	}
}

func TestTelegramConfigFromEnv(t *testing.T) {
	tests := []struct {
		name, token, owner, reason string
		enabled                    bool
		ownerID                    int64
	}{
		{name: "unset", reason: "Telegram bot disabled"},
		{name: "token only", token: "token", reason: "Telegram bot disabled: token and owner ID are both required"},
		{name: "owner only", owner: "42", reason: "Telegram bot disabled: token and owner ID are both required"},
		{name: "non-numeric owner", token: "token", owner: "nope", reason: "Telegram bot disabled: invalid owner ID"},
		{name: "zero owner", token: "token", owner: "0", reason: "Telegram bot disabled: invalid owner ID"},
		{name: "negative owner", token: "token", owner: "-1", reason: "Telegram bot disabled: invalid owner ID"},
		{name: "enabled", token: "token", owner: "42", enabled: true, ownerID: 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TELEGRAM_BOT_TOKEN", tt.token)
			t.Setenv("TELEGRAM_OWNER_ID", tt.owner)
			got := telegramConfigFromEnv()
			wantToken := ""
			if tt.enabled {
				wantToken = tt.token
			}
			if got.enabled != tt.enabled || got.token != wantToken || got.ownerID != tt.ownerID || got.reason != tt.reason {
				t.Fatalf("telegramConfigFromEnv() = %+v", got)
			}
		})
	}
}

type fakeTelegramService struct {
	started  chan struct{}
	shutdown bool
	flushed  bool
}

func (f *fakeTelegramService) Start(context.Context) { close(f.started) }
func (f *fakeTelegramService) BeginShutdown()        { f.shutdown = true }
func (f *fakeTelegramService) Flush(context.Context) error {
	f.flushed = true
	return nil
}

func TestRunLifecycle(t *testing.T) {
	for _, githubClientID := range []string{"", "client"} {
		t.Run("github="+githubClientID, func(t *testing.T) {
			t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
			t.Setenv("LISTEN_ADDR", "127.0.0.1:0")
			t.Setenv("TELEGRAM_BOT_TOKEN", "")
			t.Setenv("TELEGRAM_OWNER_ID", "")
			t.Setenv("GITHUB_CLIENT_ID", githubClientID)
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(25*time.Millisecond, cancel)
			run(ctx)
		})
	}
}

func TestRunTelegramLifecycleAndServerError(t *testing.T) {
	oldFactory := newTelegramService
	t.Cleanup(func() { newTelegramService = oldFactory })
	fake := &fakeTelegramService{started: make(chan struct{})}
	newTelegramService = func(string, int64, string, *control.VPN) (telegramService, error) {
		return fake, nil
	}
	t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("LISTEN_ADDR", "invalid-address")
	t.Setenv("TELEGRAM_BOT_TOKEN", "token")
	t.Setenv("TELEGRAM_OWNER_ID", "42")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(25*time.Millisecond, cancel)
	run(ctx)
	if !fake.shutdown || !fake.flushed {
		t.Fatalf("telegram lifecycle: shutdown=%v flushed=%v", fake.shutdown, fake.flushed)
	}
	select {
	case <-fake.started:
	default:
		t.Fatal("telegram service was not started")
	}

	newTelegramService = func(string, int64, string, *control.VPN) (telegramService, error) {
		return nil, errors.New("bad token")
	}
	ctx, cancel = context.WithCancel(context.Background())
	time.AfterFunc(25*time.Millisecond, cancel)
	run(ctx)
}
