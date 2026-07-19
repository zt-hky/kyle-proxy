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

type telegramClient interface {
	DeleteWebhook(context.Context, *bot.DeleteWebhookParams) (bool, error)
	SetMyCommands(context.Context, *bot.SetMyCommandsParams) (bool, error)
	SendMessage(context.Context, *bot.SendMessageParams) (*models.Message, error)
	DeleteMessage(context.Context, *bot.DeleteMessageParams) (bool, error)
	AnswerCallbackQuery(context.Context, *bot.AnswerCallbackQueryParams) (bool, error)
	Start(context.Context)
}

type vpnController interface {
	Connect(control.ConnectOptions) error
	SubmitOTP(string) error
	Disconnect() error
	Status() vpn.Status
	OnEvent(func(vpn.Event))
	HasSavedOTP() bool
}

type Service struct {
	bot             telegramClient
	ownerID         int64
	access          *AccessStore
	controller      vpnController
	now             func() time.Time
	authorizationMu sync.Mutex
	mu              sync.Mutex
	stopping        bool
	pending         map[int64]pendingOTP
	eventMu         sync.Mutex
	eventCond       *sync.Cond
	events          []vpn.Event
	eventHead       int
	eventInFlight   bool
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
	s := newService(ownerID, access, controller, nil)
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
	return s, nil
}

func newService(ownerID int64, access *AccessStore, controller vpnController, client telegramClient) *Service {
	s := &Service{
		bot:        client,
		ownerID:    ownerID,
		access:     access,
		controller: controller,
		now:        time.Now,
		pending:    make(map[int64]pendingOTP),
	}
	s.eventCond = sync.NewCond(&s.eventMu)
	controller.OnEvent(s.notify)
	return s
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
	s.BeginShutdown()
	s.eventMu.Lock()
	s.eventStopping = true
	s.eventCond.Broadcast()
	for s.eventHead < len(s.events) || s.eventInFlight {
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

func (s *Service) isStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func privateIdentity(update *models.Update) (chatID, userID int64, ok bool) {
	if update == nil {
		return 0, 0, false
	}
	if update.Message != nil && update.Message.From != nil {
		chat := update.Message.Chat
		if chat.Type == models.ChatTypePrivate && chat.ID == update.Message.From.ID {
			return chat.ID, update.Message.From.ID, true
		}
	}
	if update.CallbackQuery != nil && update.CallbackQuery.Message.Message != nil {
		chat := update.CallbackQuery.Message.Message.Chat
		if chat.Type == models.ChatTypePrivate && chat.ID == update.CallbackQuery.From.ID {
			return chat.ID, update.CallbackQuery.From.ID, true
		}
	}
	return 0, 0, false
}

// allowed must be called while authorizationMu is held for any operation that
// mutates access or invokes the VPN controller.
func (s *Service) allowed(update *models.Update) (int64, bool) {
	if s.isStopping() {
		return 0, false
	}
	chatID, userID, ok := privateIdentity(update)
	if !ok {
		return 0, false
	}
	if userID == s.ownerID {
		return chatID, true
	}
	r, ok := s.access.Get(userID)
	return chatID, ok && r.Status == AccessApproved
}

func (s *Service) start(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if s.isStopping() {
		return
	}
	chat, id, ok := privateIdentity(u)
	if !ok {
		return
	}
	if id == s.ownerID {
		s.sendMenu(ctx, chat)
		return
	}
	if old, exists := s.access.Get(id); exists {
		switch old.Status {
		case AccessApproved:
			s.sendMenu(ctx, chat)
		case AccessPending:
			s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Access request is pending owner approval."})
		case AccessDenied:
			s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Access request was denied."})
		}
		return
	}
	now := s.now()
	r := AccessRecord{UserID: id, ChatID: chat, Username: u.Message.From.Username, DisplayName: displayName(u.Message.From), Status: AccessPending, RequestedAt: now}
	if err := s.access.Upsert(r); err != nil {
		log.Printf("telegram access save failed: %v", err)
		return
	}
	s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Access request is pending owner approval."})
	s.send(ctx, &bot.SendMessageParams{ChatID: s.ownerID, Text: fmt.Sprintf("Access request from %s (%d)", r.DisplayName, id), ReplyMarkup: &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{{{Text: "Approve", CallbackData: "access:approve:" + fmt.Sprint(id)}, {Text: "Deny", CallbackData: "access:deny:" + fmt.Sprint(id)}}}}})
}

func (s *Service) menu(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if chat, ok := s.allowed(u); ok {
		s.sendMenu(ctx, chat)
	}
}

func (s *Service) status(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if chat, ok := s.allowed(u); ok {
		s.sendStatus(ctx, chat)
	}
}

func (s *Service) accessCommand(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	_, id, _ := privateIdentity(u)
	if id != s.ownerID {
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
	s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: text})
}

func (s *Service) connect(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	_, userID, _ := privateIdentity(u)
	s.connectLocked(ctx, chat, userID)
}

func (s *Service) connectLocked(ctx context.Context, chat, userID int64) {
	if !s.controller.HasSavedOTP() {
		msg, err := s.bot.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Enter the initial GlobalProtect OTP.", ReplyMarkup: &models.ForceReply{ForceReply: true, InputFieldPlaceholder: "OTP"}})
		if err != nil {
			return
		}
		s.mu.Lock()
		s.pending[userID] = pendingOTP{ChatID: chat, PromptMessageID: msg.ID, Kind: "initial", ExpiresAt: s.now().Add(120 * time.Second)}
		s.mu.Unlock()
		return
	}
	if err := s.controller.Connect(control.ConnectOptions{}); err != nil {
		s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Connect failed: " + err.Error()})
		return
	}
	s.sendStatus(ctx, chat)
}

func (s *Service) text(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok || u.Message == nil {
		return
	}
	_, userID, _ := privateIdentity(u)

	s.mu.Lock()
	prompt, exists := s.pending[userID]
	matchesReply := exists && prompt.ChatID == chat && u.Message.ReplyToMessage != nil && u.Message.ReplyToMessage.ID == prompt.PromptMessageID
	if matchesReply {
		delete(s.pending, userID)
	}
	s.mu.Unlock()
	if !matchesReply {
		return
	}

	s.deleteMessage(ctx, chat, prompt.PromptMessageID, "prompt")
	s.deleteMessage(ctx, chat, u.Message.ID, "OTP")
	if !s.now().Before(prompt.ExpiresAt) {
		return
	}

	var err error
	if prompt.Kind == "followup" {
		err = s.controller.SubmitOTP(u.Message.Text)
	} else {
		err = s.controller.Connect(control.ConnectOptions{OTP: u.Message.Text})
	}
	if err != nil {
		s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: "OTP failed: " + err.Error()})
		return
	}
	s.sendStatus(ctx, chat)
}

func (s *Service) deleteMessage(ctx context.Context, chat int64, messageID int, label string) {
	if _, err := s.bot.DeleteMessage(ctx, &bot.DeleteMessageParams{ChatID: chat, MessageID: messageID}); err != nil {
		// Telegram errors do not need message contents to be actionable. Logging
		// only the error type prevents an OTP echoed by an adapter from leaking.
		log.Printf("telegram %s deletion failed message=%d error=%T", label, messageID, err)
	}
}

func (s *Service) accessCallback(ctx context.Context, _ *bot.Bot, u *models.Update) {
	if u == nil || u.CallbackQuery == nil {
		return
	}
	s.answerCallback(ctx, u.CallbackQuery.ID)
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	if _, ok := s.allowed(u); !ok || u.CallbackQuery.From.ID != s.ownerID {
		return
	}
	parts := strings.Split(u.CallbackQuery.Data, ":")
	if len(parts) != 3 {
		return
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || id == s.ownerID {
		return
	}
	rec, ok := s.access.Get(id)
	if !ok {
		return
	}
	now := s.now()
	switch parts[1] {
	case "approve":
		if rec.Status != AccessPending && rec.Status != AccessDenied {
			return
		}
		rec.Status, rec.DecidedAt = AccessApproved, &now
		if err := s.access.Upsert(rec); err != nil {
			log.Printf("telegram access decision failed: %v", err)
			return
		}
	case "deny":
		if rec.Status != AccessPending {
			return
		}
		rec.Status, rec.DecidedAt = AccessDenied, &now
		if err := s.access.Upsert(rec); err != nil {
			log.Printf("telegram access decision failed: %v", err)
			return
		}
	case "revoke":
		if rec.Status != AccessApproved {
			return
		}
		if err := s.access.Delete(id); err != nil {
			log.Printf("telegram access revoke failed: %v", err)
			return
		}
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return
	default:
		return
	}
	s.send(ctx, &bot.SendMessageParams{ChatID: rec.ChatID, Text: fmt.Sprintf("Access status: %s", rec.Status)})
}

func (s *Service) disconnect(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	s.disconnectLocked(ctx, chat)
}

func (s *Service) disconnectLocked(ctx context.Context, chat int64) {
	if err := s.controller.Disconnect(); err != nil {
		s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Disconnect failed: " + err.Error()})
		return
	}
	s.sendStatus(ctx, chat)
}

func (s *Service) callback(ctx context.Context, _ *bot.Bot, u *models.Update) {
	if u == nil || u.CallbackQuery == nil {
		return
	}
	s.answerCallback(ctx, u.CallbackQuery.ID)
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	_, userID, _ := privateIdentity(u)
	switch u.CallbackQuery.Data {
	case "vpn:status", "menu:main":
		s.sendStatus(ctx, chat)
	case "vpn:connect":
		s.connectLocked(ctx, chat, userID)
	case "vpn:disconnect":
		s.disconnectLocked(ctx, chat)
	case "vpn:otp":
		s.otpPromptLocked(ctx, chat, userID)
	}
}

func (s *Service) otpPrompt(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	_, userID, _ := privateIdentity(u)
	s.otpPromptLocked(ctx, chat, userID)
}

func (s *Service) otpPromptLocked(ctx context.Context, chat, userID int64) {
	if !s.controller.Status().AwaitingOTP {
		return
	}
	msg, err := s.bot.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: "Enter the next GlobalProtect OTP.", ReplyMarkup: &models.ForceReply{ForceReply: true, InputFieldPlaceholder: "OTP"}})
	if err != nil {
		return
	}
	s.mu.Lock()
	s.pending[userID] = pendingOTP{ChatID: chat, PromptMessageID: msg.ID, Kind: "followup", ExpiresAt: s.now().Add(120 * time.Second)}
	s.mu.Unlock()
}

func (s *Service) send(ctx context.Context, params *bot.SendMessageParams) {
	_, _ = s.bot.SendMessage(ctx, params)
}

func (s *Service) answerCallback(ctx context.Context, id string) {
	_, _ = s.bot.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: id})
}

func (s *Service) sendMenu(ctx context.Context, chat int64) { s.sendStatus(ctx, chat) }

func (s *Service) sendStatus(ctx context.Context, chat int64) {
	st := s.controller.Status()
	text := fmt.Sprintf("GlobalProtect · %s\n%s", strings.ToUpper(string(st.State)), st.Detail)
	buttons := []models.InlineKeyboardButton{{Text: "Status", CallbackData: "vpn:status", Style: "primary"}}
	switch st.State {
	case vpn.StateDisconnected, vpn.StateError:
		buttons = append(buttons, models.InlineKeyboardButton{Text: "Connect", CallbackData: "vpn:connect", Style: "success"})
	case vpn.StateConnecting:
		if st.AwaitingOTP {
			buttons = append(buttons, models.InlineKeyboardButton{Text: "Enter OTP", CallbackData: "vpn:otp", Style: "primary"})
		}
		buttons = append(buttons, models.InlineKeyboardButton{Text: "Disconnect", CallbackData: "vpn:disconnect", Style: "danger"})
	case vpn.StateConnected:
		buttons = append(buttons, models.InlineKeyboardButton{Text: "Disconnect", CallbackData: "vpn:disconnect", Style: "danger"})
	}
	s.send(ctx, &bot.SendMessageParams{ChatID: chat, Text: text, ReplyMarkup: &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{buttons}}})
}

func (s *Service) notify(e vpn.Event) {
	// State changes invalidate prompts that no longer match the VPN's needs.
	s.mu.Lock()
	for id, prompt := range s.pending {
		if prompt.Kind == "followup" && !e.Status.AwaitingOTP || prompt.Kind == "initial" && e.Kind == vpn.EventKindState {
			delete(s.pending, id)
		}
	}
	s.mu.Unlock()

	s.eventMu.Lock()
	if !s.eventStopping {
		s.events = append(s.events, e)
		s.eventCond.Signal()
	}
	s.eventMu.Unlock()
}

func (s *Service) dispatchEvents(ctx context.Context) {
	stopCancellationWakeup := context.AfterFunc(ctx, func() {
		s.eventMu.Lock()
		s.eventStopping = true
		s.eventCond.Broadcast()
		s.eventMu.Unlock()
	})
	defer stopCancellationWakeup()

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
		s.eventInFlight = true
		s.eventMu.Unlock()

		recipientSet := map[int64]struct{}{s.ownerID: {}}
		for _, r := range s.access.Snapshot() {
			if r.Status == AccessApproved {
				recipientSet[r.ChatID] = struct{}{}
			}
		}
		recipients := make([]int64, 0, len(recipientSet))
		for chat := range recipientSet {
			recipients = append(recipients, chat)
		}
		sort.Slice(recipients, func(i, j int) bool { return recipients[i] < recipients[j] })
		text := fmt.Sprintf("GlobalProtect · %s\n%s", strings.ToUpper(e.Name), e.Detail)
		for _, chat := range recipients {
			if _, err := s.bot.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: text}); err != nil {
				log.Printf("telegram notification failed chat=%d error=%T", chat, err)
			}
		}

		s.eventMu.Lock()
		s.eventInFlight = false
		if s.eventHead > 64 && s.eventHead*2 >= len(s.events) {
			s.events = append([]vpn.Event(nil), s.events[s.eventHead:]...)
			s.eventHead = 0
		}
		s.eventCond.Broadcast()
		s.eventMu.Unlock()
	}
}

func displayName(u *models.User) string {
	if u.FirstName+" "+u.LastName != " " {
		return strings.TrimSpace(u.FirstName + " " + u.LastName)
	}
	return u.Username
}
