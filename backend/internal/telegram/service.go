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
	SendMessageDraft(context.Context, *bot.SendMessageDraftParams) (bool, error)
	EditMessageText(context.Context, *bot.EditMessageTextParams) (*models.Message, error)
	DeleteMessages(context.Context, *bot.DeleteMessagesParams) (bool, error)
	AnswerCallbackQuery(context.Context, *bot.AnswerCallbackQueryParams) (bool, error)
	Start(context.Context)
}

type vpnController interface {
	Connect(control.ConnectOptions) error
	SubmitOTP(string) error
	Disconnect() error
	Status() vpn.Status
	Logs() []string
	OnEvent(func(vpn.Event))
	OnLog(func())
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
	eventStreams    *eventStreams
	logStreams      *logStreams
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
		bot.WithMessageTextHandler("logs", bot.MatchTypeCommand, s.logs),
		bot.WithCallbackQueryDataHandler("vpn:", bot.MatchTypePrefix, s.callback),
		bot.WithCallbackQueryDataHandler("access:", bot.MatchTypePrefix, s.accessCallback),
		bot.WithCallbackQueryDataHandler("menu:", bot.MatchTypePrefix, s.callback),
		bot.WithCallbackQueryDataHandler("logs:", bot.MatchTypePrefix, s.logsCallback),
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
	s.logStreams = newLogStreams(s)
	s.eventStreams = newEventStreams(s)
	s.eventCond = sync.NewCond(&s.eventMu)
	controller.OnEvent(s.notify)
	controller.OnLog(s.logStreams.notify)
	return s
}

func (s *Service) Start(ctx context.Context) {
	_, err := s.bot.DeleteWebhook(ctx, &bot.DeleteWebhookParams{DropPendingUpdates: false})
	if err != nil && !strings.Contains(err.Error(), "unexpected end of JSON input") {
		log.Printf("telegram webhook setup failed: %v", err)
		return
	}
	if err != nil {
		log.Printf("telegram webhook returned an empty response; continuing with polling: %v", err)
	}
	_, err = s.bot.SetMyCommands(ctx, &bot.SetMyCommandsParams{Commands: []models.BotCommand{{Command: "start", Description: "Start"}, {Command: "menu", Description: "VPN menu"}, {Command: "status", Description: "VPN status"}, {Command: "logs", Description: "Live VPN logs"}, {Command: "connect", Description: "Connect VPN"}, {Command: "disconnect", Description: "Disconnect VPN"}, {Command: "access", Description: "Manage access"}}})
	if err != nil {
		log.Printf("telegram command setup failed: %v", err)
		return
	}
	go s.dispatchEvents(ctx)
	defer s.BeginShutdown()
	s.bot.Start(ctx)
}

func (s *Service) BeginShutdown() {
	s.mu.Lock()
	alreadyStopping := s.stopping
	s.stopping = true
	s.mu.Unlock()
	if !alreadyStopping {
		s.logStreams.shutdown()
	}
}

func (s *Service) Flush(ctx context.Context) error {
	s.BeginShutdown()
	s.eventMu.Lock()
	s.eventStopping = true
	s.eventCond.Broadcast()
	s.eventMu.Unlock()
	if err := s.logStreams.wait(ctx); err != nil {
		return err
	}
	s.eventMu.Lock()
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
	return s.eventStreams.shutdown(ctx)
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
	chatID, userID, ok := privateIdentity(update)
	if !ok || !s.userAllowedLocked(userID) {
		return 0, false
	}
	return chatID, true
}

func (s *Service) userAllowedLocked(userID int64) bool {
	if s.isStopping() {
		return false
	}
	if userID == s.ownerID {
		return true
	}
	r, ok := s.access.Get(userID)
	return ok && r.Status == AccessApproved
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
			s.sendHTML(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatAccessDecision(AccessPending)})
		case AccessDenied:
			s.sendHTML(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatAccessDecision(AccessDenied)})
		}
		return
	}
	now := s.now()
	r := AccessRecord{UserID: id, ChatID: chat, Username: u.Message.From.Username, DisplayName: displayName(u.Message.From), Status: AccessPending, RequestedAt: now}
	if err := s.access.Upsert(r); err != nil {
		log.Printf("telegram access save failed: %v", err)
		return
	}
	s.sendHTML(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatAccessDecision(AccessPending)})
	s.sendHTML(ctx, &bot.SendMessageParams{ChatID: s.ownerID, Text: formatAccessRequest(r), ReplyMarkup: &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{{{Text: "Approve", CallbackData: "access:approve:" + fmt.Sprint(id)}, {Text: "Deny", CallbackData: "access:deny:" + fmt.Sprint(id)}}}}})
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
	s.sendHTML(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatAccessRecords(s.access.Snapshot())})
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
		msg, err := s.bot.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatOTPPrompt("initial"), ParseMode: models.ParseModeHTML, ReplyMarkup: &models.ForceReply{ForceReply: true, InputFieldPlaceholder: "OTP"}})
		if err != nil {
			return
		}
		s.mu.Lock()
		s.pending[userID] = pendingOTP{ChatID: chat, PromptMessageID: msg.ID, Kind: "initial", ExpiresAt: s.now().Add(120 * time.Second)}
		s.mu.Unlock()
		return
	}
	s.logStreams.startActionLocked(ctx, chat, userID, "connect")
	if err := s.controller.Connect(control.ConnectOptions{}); err != nil {
		s.logStreams.completeAction(ctx, "connect", false)
	}
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

	s.deleteMessages(ctx, chat, []int{prompt.PromptMessageID, u.Message.ID}, "OTP claim")
	if !s.now().Before(prompt.ExpiresAt) {
		return
	}

	var err error
	if prompt.Kind == "followup" {
		err = s.controller.SubmitOTP(u.Message.Text)
	} else {
		s.logStreams.startActionLocked(ctx, chat, userID, "connect")
		err = s.controller.Connect(control.ConnectOptions{OTP: u.Message.Text})
	}
	if err != nil && !s.logStreams.completeAction(ctx, "connect", false) {
		s.sendHTML(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatOTPError()})
	}
}

func (s *Service) deleteMessages(ctx context.Context, chat int64, messageIDs []int, label string) {
	seen := make(map[int]struct{}, len(messageIDs))
	filtered := make([]int, 0, len(messageIDs))
	for _, id := range messageIDs {
		if id == 0 {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		filtered = append(filtered, id)
	}
	if len(filtered) == 0 {
		return
	}
	if _, err := s.bot.DeleteMessages(ctx, &bot.DeleteMessagesParams{ChatID: chat, MessageIDs: filtered}); err != nil {
		log.Printf("telegram %s deletion failed messages=%v error=%T", label, filtered, err)
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
		s.logStreams.revokeLocked(ctx, id)
		return
	default:
		return
	}
	s.sendHTML(ctx, &bot.SendMessageParams{ChatID: rec.ChatID, Text: formatAccessDecision(rec.Status)})
}

func (s *Service) disconnect(ctx context.Context, _ *bot.Bot, u *models.Update) {
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	_, userID, _ := privateIdentity(u)
	s.disconnectLocked(ctx, chat, userID)
}

func (s *Service) disconnectLocked(ctx context.Context, chat, userID int64) {
	s.logStreams.startActionLocked(ctx, chat, userID, "disconnect")
	if err := s.controller.Disconnect(); err != nil {
		s.logStreams.completeAction(ctx, "disconnect", false)
		return
	}
	s.logStreams.completeAction(ctx, "disconnect", true)
}

func (s *Service) callback(ctx context.Context, _ *bot.Bot, u *models.Update) {
	if u == nil || u.CallbackQuery == nil {
		return
	}
	s.answerCallback(ctx, u.CallbackQuery.ID)
	switch u.CallbackQuery.Data {
	case "vpn:status", "vpn:connect", "vpn:disconnect", "vpn:otp", "menu:main", "menu:logs":
	default:
		return
	}
	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chat, ok := s.allowed(u)
	if !ok {
		return
	}
	_, userID, _ := privateIdentity(u)
	if u.CallbackQuery.Message.Message != nil {
		s.deleteMessages(ctx, chat, []int{u.CallbackQuery.Message.Message.ID}, "menu origin")
	}
	switch u.CallbackQuery.Data {
	case "vpn:status", "menu:main":
		s.sendStatus(ctx, chat)
	case "vpn:connect":
		s.connectLocked(ctx, chat, userID)
	case "vpn:disconnect":
		s.disconnectLocked(ctx, chat, userID)
	case "vpn:otp":
		s.otpPromptLocked(ctx, chat, userID)
	case "menu:logs":
		s.logStreams.startLocked(ctx, chat, userID)
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
	msg, err := s.bot.SendMessage(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatOTPPrompt("next"), ParseMode: models.ParseModeHTML, ReplyMarkup: &models.ForceReply{ForceReply: true, InputFieldPlaceholder: "OTP"}})
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

func (s *Service) sendHTML(ctx context.Context, params *bot.SendMessageParams) {
	params.ParseMode = models.ParseModeHTML
	s.send(ctx, params)
}

func (s *Service) answerCallback(ctx context.Context, id string) {
	_, _ = s.bot.AnswerCallbackQuery(ctx, &bot.AnswerCallbackQueryParams{CallbackQueryID: id})
}

func (s *Service) sendMenu(ctx context.Context, chat int64) { s.sendStatus(ctx, chat) }

func (s *Service) sendStatus(ctx context.Context, chat int64) {
	st := s.controller.Status()
	rows := [][]models.InlineKeyboardButton{{
		{Text: "Status", CallbackData: "vpn:status", Style: "primary"},
		{Text: "Logs", CallbackData: "menu:logs"},
	}}
	var actions []models.InlineKeyboardButton
	switch st.State {
	case vpn.StateDisconnected, vpn.StateError:
		actions = append(actions, models.InlineKeyboardButton{Text: "Connect", CallbackData: "vpn:connect", Style: "success"})
	case vpn.StateConnecting:
		if st.AwaitingOTP {
			actions = append(actions, models.InlineKeyboardButton{Text: "Enter OTP", CallbackData: "vpn:otp", Style: "primary"})
		}
		actions = append(actions, models.InlineKeyboardButton{Text: "Disconnect", CallbackData: "vpn:disconnect", Style: "danger"})
	case vpn.StateConnected:
		actions = append(actions, models.InlineKeyboardButton{Text: "Disconnect", CallbackData: "vpn:disconnect", Style: "danger"})
	}
	if len(actions) != 0 {
		rows = append(rows, actions)
	}
	s.sendHTML(ctx, &bot.SendMessageParams{ChatID: chat, Text: formatStatus(st), ReplyMarkup: &models.InlineKeyboardMarkup{InlineKeyboard: rows}})
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
	if s.logStreams.handleEvent(context.Background(), e) {
		return
	}

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
		for _, chat := range recipients {
			s.eventStreams.push(ctx, chat, e)
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
