package telegram

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"globalprotect-manager/internal/control"
	"globalprotect-manager/internal/vpn"
)

type Service struct {
	bot             *bot.Bot
	ownerID         int64
	access          *AccessStore
	controller      *control.VPN
	authorizationMu sync.Mutex
	mu              sync.Mutex
	stopping        bool
	pending         map[int64]pendingOTP
	eventMu         sync.Mutex
	eventCond       *sync.Cond
	events          []vpn.Event
	eventHead       int
	eventStopping   bool
}
type pendingOTP struct {
	ChatID          int64
	PromptMessageID int
	Kind            string
	ExpiresAt       time.Time
}

func New(token string, ownerID int64, accessPath string, controller *control.VPN) (*Service, error) {
	access, err := NewAccessStore(accessPath, ownerID)
	if err != nil {
		return nil, err
	}
	s := &Service{ownerID: ownerID, access: access, controller: controller, pending: make(map[int64]pendingOTP)}
	b, err := bot.New(token,
		bot.WithMessageTextHandler("start", bot.MatchTypeCommand, s.start),
		bot.WithMessageTextHandler("menu", bot.MatchTypeCommand, s.menu),
		bot.WithMessageTextHandler("status", bot.MatchTypeCommand, s.status),
		bot.WithMessageTextHandler("access", bot.MatchTypeCommand, s.accessCommand),
		bot.WithMessageTextHandler("connect", bot.MatchTypeCommand, s.connect),
		bot.WithMessageTextHandler("disconnect", bot.MatchTypeCommand, s.disconnect),
		bot.WithCallbackQueryDataHandler("vpn:", bot.MatchTypePrefix, s.callback),
		bot.WithCallbackQueryDataHandler("access:", bot.MatchTypePrefix, s.accessCallback),
		bot.WithCallbackQueryDataHandler("menu:", bot.MatchTypePrefix, s.callback),
		bot.WithDefaultHandler(s.text),
	)
	if err != nil {
		return nil, err
	}
	s.bot = b
	s.eventCond = sync.NewCond(&s.eventMu)
	controller.OnEvent(s.notify)
	return s, nil
}
func (s *Service) Start(ctx context.Context) {
	if _, err := s.bot.DeleteWebhook(ctx, &bot.DeleteWebhookParams{DropPendingUpdates: false}); err != nil {
		log.Printf("telegram webhook setup failed: %v", err)
		return
	}
	_, err := s.bot.SetMyCommands(ctx, &bot.SetMyCommandsParams{Commands: []models.BotCommand{{Command: "start", Description: "Start"}, {Command: "menu", Description: "VPN menu"}, {Command: "status", Description: "VPN status"}, {Command: "connect", Description: "Connect VPN"}, {Command: "disconnect", Description: "Disconnect VPN"}, {Command: "access", Description: "Manage access"}}})
	if err != nil {
		log.Printf("telegram command setup failed: %v", err)
		return
	}
	go s.dispatchEvents(ctx)

	s.bot.Start(ctx)
}

func (s *Service) BeginShutdown() {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
}

func (s *Service) Flush(ctx context.Context) error {
	s.mu.Lock()
	s.stopping = true
	s.mu.Unlock()
	s.eventMu.Lock()
	s.eventStopping = true
	s.eventCond.Broadcast()
	for s.eventHead < len(s.events) {
		if ctx.Err() != nil {
			s.eventMu.Unlock()
			return ctx.Err()
		}
		s.eventMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
		s.eventMu.Lock()
	}
	s.events = nil
	s.eventHead = 0
	s.eventMu.Unlock()
	return nil
}

func (s *Service) allowed(update *models.Update) (int64, bool) {
	var chatID, userID int64
	s.mu.Lock()
	stopping := s.stopping
	s.mu.Unlock()
	if stopping {
		return 0, false
	}
	if update.Message != nil {
		chatID = update.Message.Chat.ID
		userID = update.Message.From.ID
	} else if update.CallbackQuery != nil && update.CallbackQuery.Message.Message != nil {
		chatID = update.CallbackQuery.Message.Message.Chat.ID
		userID = update.CallbackQuery.From.ID
	} else {
		return 0, false
	}
	if chatID != userID {
		return 0, false
	}
	if userID == s.ownerID {
		return chatID, true
	}
	r, ok := s.access.Get(userID)
	return chatID, ok && r.Status == AccessApproved
}
func (s *Service) start(ctx context.Context, b *bot.Bot, u *models.Update) {
	if u.Message == nil || u.Message.Chat.ID != u.Message.From.ID {
		return
	}
	id := u.Message.From.ID
	if id == s.ownerID {
		s.sendMenu(ctx, b, u.Message.Chat.ID)
		return
	}
	if r, ok := s.access.Get(id); ok && r.Status == AccessApproved {
		s.sendMenu(ctx, b, u.Message.Chat.ID)
		return
	}
	now := time.Now()
	r := AccessRecord{UserID: id, ChatID: u.Message.Chat.ID, Username: u.Message.From.Username, DisplayName: displayName(u.Message.From), Status: AccessPending, RequestedAt: now}
	if old, ok := s.access.Get(id); ok && old.Status == AccessPending {
		return
	}
	if err := s.access.Upsert(r); err != nil {
		log.Printf("telegram access save failed: %v", err)
		return
	}
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: u.Message.Chat.ID, Text: "Access request is pending owner approval."})
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: s.ownerID, Text: fmt.Sprintf("Access request from %s (%d)", r.DisplayName, id), ReplyMarkup: &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{{{Text: "Approve", CallbackData: "access:approve:" + fmt.Sprint(id)}, {Text: "Deny", CallbackData: "access:deny:" + fmt.Sprint(id)}}}}})
}
func (s *Service) menu(ctx context.Context, b *bot.Bot, u *models.Update) {
	if chat, ok := s.allowed(u); ok {
		s.sendMenu(ctx, b, chat)
	}
}
func (s *Service) status(ctx context.Context, b *bot.Bot, u *models.Update) {
	if chat, ok := s.allowed(u); ok {
		s.sendStatus(ctx, b, chat)
	}
}
func (s *Service) accessCommand(ctx context.Context, b *bot.Bot, u *models.Update) {
	if u.Message == nil || u.Message.Chat.ID != u.Message.From.ID || u.Message.From.ID != s.ownerID {
		return
	}
	records := s.access.Snapshot()
	text := "Access records:\n"
	for _, r := range records {
		text += fmt.Sprintf("%d · %s · %s\n", r.UserID, r.DisplayName, r.Status)
	}
	if len(records) == 0 {
		text += "(none)"
	}
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: s.ownerID, Text: text})
}
func (s *Service) connect(ctx context.Context, b *bot.Bot, u *models.Update) {
	if chat, ok := s.allowed(u); ok {
		s.authorizationMu.Lock()
		defer s.authorizationMu.Unlock()
		if !s.controller.HasSavedOTP() {
			var id int64
			if u.Message != nil {
				id = u.Message.From.ID
			} else {
				id = u.CallbackQuery.From.ID
			}
			msg, err := b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Enter the initial GlobalProtect OTP.", ReplyMarkup: &models.ForceReply{ForceReply: true, InputFieldPlaceholder: "OTP"}})
			if err != nil {
				return
			}
			s.mu.Lock()
			s.pending[id] = pendingOTP{ChatID: chat, PromptMessageID: msg.ID, Kind: "initial", ExpiresAt: time.Now().Add(120 * time.Second)}
			s.mu.Unlock()
			return
		}
		if err := s.controller.Connect(control.ConnectOptions{}); err != nil {
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Connect failed: " + err.Error()})
			return
		}
		s.sendStatus(ctx, b, chat)
	}
}

func (s *Service) text(ctx context.Context, b *bot.Bot, u *models.Update) {
	if u.Message == nil || u.Message.Chat.ID != u.Message.From.ID {
		return
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	s.mu.Lock()
	prompt, exists := s.pending[u.Message.From.ID]
	if exists {
		delete(s.pending, u.Message.From.ID)
	}
	s.mu.Unlock()
	if !exists || prompt.ChatID != chat || time.Now().After(prompt.ExpiresAt) {
		return
	}
	if _, err := b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chat, MessageID: prompt.PromptMessageID}); err != nil {
		log.Printf("telegram prompt deletion failed message=%d: %v", prompt.PromptMessageID, err)
	}
	if _, err := b.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chat, MessageID: u.Message.ID}); err != nil {
		log.Printf("telegram OTP deletion failed message=%d: %v", u.Message.ID, err)
	}
	var err error
	if prompt.Kind == "followup" {
		err = s.controller.SubmitOTP(u.Message.Text)
	} else {
		err = s.controller.Connect(control.ConnectOptions{OTP: u.Message.Text})
	}
	if err != nil {
		b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: "OTP failed: " + err.Error()})
		return
	}
	s.sendStatus(ctx, b, chat)
}
func (s *Service) accessCallback(ctx context.Context, b *bot.Bot, u *models.Update) {
	if u.CallbackQuery == nil {
		return
	}
	b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: u.CallbackQuery.ID})
	if u.CallbackQuery.From.ID != s.ownerID || u.CallbackQuery.Message.Message == nil || u.CallbackQuery.Message.Message.Chat.ID != s.ownerID {
		return
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	parts := strings.Split(u.CallbackQuery.Data, ":")
	if len(parts) != 3 {
		return
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return
	}
	rec, ok := s.access.Get(id)
	if !ok {
		return
	}
	now := time.Now()
	switch parts[1] {
	case "approve":
		rec.Status, rec.DecidedAt = AccessApproved, &now
	case "deny":
		rec.Status, rec.DecidedAt = AccessDenied, &now
	case "revoke":
		if err := s.access.Delete(id); err != nil {
			log.Printf("telegram access revoke failed: %v", err)
		}
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return
	default:
		return
	}
	if err := s.access.Upsert(rec); err != nil {
		log.Printf("telegram access decision failed: %v", err)
		return
	}
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: rec.ChatID, Text: fmt.Sprintf("Access status: %s", rec.Status)})
}

func (s *Service) disconnect(ctx context.Context, b *bot.Bot, u *models.Update) {
	if chat, ok := s.allowed(u); ok {
		s.authorizationMu.Lock()
		defer s.authorizationMu.Unlock()
		if err := s.controller.Disconnect(); err != nil {
			b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Disconnect failed: " + err.Error()})
			return
		}
		s.sendStatus(ctx, b, chat)
	}
}

func (s *Service) callback(ctx context.Context, b *bot.Bot, u *models.Update) {
	if u.CallbackQuery == nil {
		return
	}
	b.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: u.CallbackQuery.ID})
	if chat, ok := s.allowed(u); ok {
		switch u.CallbackQuery.Data {
		case "vpn:status", "menu:main":
			s.sendStatus(ctx, b, chat)
		case "vpn:connect":
			s.connect(ctx, b, u)
		case "vpn:disconnect":
			s.disconnect(ctx, b, u)
		case "vpn:otp":
			s.otpPrompt(ctx, b, u)
		}
	}
}
func (s *Service) otpPrompt(ctx context.Context, b *bot.Bot, u *models.Update) {
	chat, ok := s.allowed(u)
	if !ok || !s.controller.Status().AwaitingOTP {
		return
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	msg, err := b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Enter the next GlobalProtect OTP.", ReplyMarkup: &models.ForceReply{ForceReply: true, InputFieldPlaceholder: "OTP"}})
	if err != nil {
		return
	}
	s.mu.Lock()
	s.pending[u.CallbackQuery.From.ID] = pendingOTP{ChatID: chat, PromptMessageID: msg.ID, Kind: "followup", ExpiresAt: time.Now().Add(120 * time.Second)}
	s.mu.Unlock()
}

func (s *Service) sendMenu(ctx context.Context, b *bot.Bot, chat int64) { s.sendStatus(ctx, b, chat) }
func (s *Service) sendStatus(ctx context.Context, b *bot.Bot, chat int64) {
	st := s.controller.Status()
	text := fmt.Sprintf("GlobalProtect · %s\n%s", strings.ToUpper(string(st.State)), st.Detail)
	buttons := []models.InlineKeyboardButton{{Text: "Status", CallbackData: "vpn:status"}}
	switch st.State {
	case vpn.StateDisconnected, vpn.StateError:
		buttons = append(buttons, models.InlineKeyboardButton{Text: "Connect", CallbackData: "vpn:connect"})
	case vpn.StateConnecting:
		if st.AwaitingOTP {
			buttons = append(buttons, models.InlineKeyboardButton{Text: "Enter OTP", CallbackData: "vpn:otp"})
		}
		buttons = append(buttons, models.InlineKeyboardButton{Text: "Disconnect", CallbackData: "vpn:disconnect"})
	case vpn.StateConnected:
		buttons = append(buttons, models.InlineKeyboardButton{Text: "Disconnect", CallbackData: "vpn:disconnect"})
	}
	b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: text, ReplyMarkup: &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{buttons}}})
}
func (s *Service) notify(e vpn.Event) {
	s.eventMu.Lock()
	if s.eventStopping {
		s.eventMu.Unlock()
		return
	}
	s.events = append(s.events, e)
	s.eventCond.Signal()
	s.eventMu.Unlock()
}

func (s *Service) dispatchEvents(ctx context.Context) {
	for {
		s.eventMu.Lock()
		for s.eventHead == len(s.events) && !s.eventStopping {
			s.eventCond.Wait()
		}
		if s.eventHead == len(s.events) && s.eventStopping {
			s.eventMu.Unlock()
			return
		}
		e := s.events[s.eventHead]
		s.eventHead++
		if s.eventHead > 64 && s.eventHead*2 >= len(s.events) {
			s.events = append([]vpn.Event(nil), s.events[s.eventHead:]...)
			s.eventHead = 0
		}
		s.eventMu.Unlock()

		s.mu.Lock()
		recipients := []int64{s.ownerID}
		for _, r := range s.access.Snapshot() {
			if r.Status == AccessApproved && r.UserID != s.ownerID {
				recipients = append(recipients, r.ChatID)
			}
		}
		b := s.bot
		s.mu.Unlock()
		sort.Slice(recipients, func(i, j int) bool { return recipients[i] < recipients[j] })
		text := fmt.Sprintf("GlobalProtect · %s\n%s", strings.ToUpper(e.Name), e.Detail)
		for _, chat := range recipients {
			if _, err := b.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: text}); err != nil {
				log.Printf("telegram notification failed chat=%d: %v", chat, err)
			}
		}
	}
}
func displayName(u *models.User) string {
	if u.FirstName+" "+u.LastName != " " {
		return strings.TrimSpace(u.FirstName + " " + u.LastName)
	}
	return u.Username
}
