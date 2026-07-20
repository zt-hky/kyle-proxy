package telegram

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"globalprotect-manager/internal/vpn"
)

const (
	logRefreshInterval = time.Second
	logDraftHeartbeat  = 20 * time.Second
	logBotTimeout      = 5 * time.Second
	logPageLines       = 20
)

type logDeliveryMode uint8

const (
	logDeliveryDraft logDeliveryMode = iota
	logDeliveryEdit
)

type logTicker interface {
	C() <-chan time.Time
	Stop()
}

type logTickerFactory func(time.Duration) logTicker

type realLogTicker struct {
	*time.Ticker
}

func (t realLogTicker) C() <-chan time.Time { return t.Ticker.C }

type logStreams struct {
	service *Service

	// Lock order is Service.authorizationMu -> mu -> logStream.mu. The run
	// loop never holds mu while acquiring authorizationMu, and wait is only
	// called after shutdown without any of these locks held.
	mu          sync.Mutex
	actions     map[string]bool
	streams     map[int64]*logStream
	stopping    bool
	wg          sync.WaitGroup
	newTicker   logTickerFactory
	nextDraftID uint64
	useDrafts   bool
}

type logStream struct {
	mu sync.Mutex

	chatID       int64
	userID       int64
	ctx          context.Context
	cancel       context.CancelFunc
	stopped      bool
	updates      chan struct{}
	deleteOnExit atomic.Bool

	current         string
	currentHasOlder bool
	mode            logDeliveryMode
	draftID         string
	lastDraftAt     time.Time
	controlMsgID    int
	controlHasOlder bool
	outputMsgID     int
	action          string
	finalLine       string
	visibleLines    int
}

func newLogStreams(service *Service) *logStreams {
	seed := uint64(service.now().UnixNano())
	if seed == 0 {
		seed = 1
	}
	return &logStreams{
		service:     service,
		actions:     make(map[string]bool),
		streams:     make(map[int64]*logStream),
		newTicker:   func(d time.Duration) logTicker { return realLogTicker{time.NewTicker(d)} },
		nextDraftID: seed,
	}
}

// startLocked requires Service.authorizationMu. It installs a manual stream.
func (l *logStreams) startLocked(ctx context.Context, chatID, userID int64) {
	l.start(ctx, chatID, userID, "")
}

// startActionLocked requires Service.authorizationMu. An action reuses an
// existing manual stream and makes it auto-stop when the action terminates.
func (l *logStreams) startActionLocked(ctx context.Context, chatID, userID int64, action string) {
	l.start(ctx, chatID, userID, action)
}

func (l *logStreams) start(ctx context.Context, chatID, userID int64, action string) {
	l.mu.Lock()
	if l.stopping {
		l.mu.Unlock()
		return
	}
	if action != "" {
		l.actions[action] = true
	}
	if stream, exists := l.streams[userID]; exists {
		if action != "" {
			stream.mu.Lock()
			stream.action = action
			stream.mu.Unlock()
			l.mu.Unlock()
			return
		}
		l.mu.Unlock()
		callCtx, cancel := context.WithTimeout(ctx, logBotTimeout)
		defer cancel()
		_, _ = l.service.bot.SendMessage(callCtx, &bot.SendMessageParams{
			ChatID: chatID, Text: "<b>Live logs are already running.</b> Use <code>/logs stop</code> first.", ParseMode: models.ParseModeHTML,
		})
		return
	}
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	draftID := l.nextDraftID
	l.nextDraftID++
	if l.nextDraftID == 0 {
		l.nextDraftID = 1
	}
	stream := &logStream{
		chatID: chatID, userID: userID, ctx: streamCtx, cancel: cancel,
		updates: make(chan struct{}, 1), draftID: strconv.FormatUint(draftID, 10), action: action,
		visibleLines: logPageLines,
	}
	l.streams[userID] = stream
	l.wg.Add(1)
	l.mu.Unlock()
	go l.run(stream)
}

// stopLocked requires Service.authorizationMu. Explicit stops finalize the
// current stream; non-explicit stops only cancel it.
func (l *logStreams) stopLocked(ctx context.Context, userID int64, explicit bool) {
	l.mu.Lock()
	stream, exists := l.streams[userID]
	if !exists {
		l.mu.Unlock()
		return
	}
	delete(l.streams, userID)
	stream.mu.Lock()
	l.mu.Unlock()

	stream.stopped = true
	stream.cancel()
	if explicit {
		l.finalizeLocked(ctx, stream)
	}
	stream.mu.Unlock()
}

// handleEvent folds lifecycle events into active action streams. It returns
// true when regular event messages should be suppressed.
func (l *logStreams) handleEvent(ctx context.Context, event vpn.Event) bool {
	l.mu.Lock()
	actions := make([]string, 0, len(l.actions))
	for action := range l.actions {
		actions = append(actions, action)
	}
	l.mu.Unlock()
	if len(actions) == 0 {
		return false
	}
	for _, action := range actions {
		if terminal, success := terminalActionEvent(action, event); terminal {
			l.completeAction(ctx, action, success)
		}
	}
	return true
}

func terminalActionEvent(action string, event vpn.Event) (terminal, success bool) {
	switch action {
	case "connect":
		if event.Kind == vpn.EventKindAction && event.Name == "connect" {
			switch event.Outcome {
			case "failed", "rejected":
				return true, false
			}
		}
		if event.Kind == vpn.EventKindState {
			switch event.Status.State {
			case vpn.StateConnected:
				return true, true
			case vpn.StateError:
				return true, false
			}
		}
	}
	return false, false
}

func (l *logStreams) completeAction(ctx context.Context, action string, success bool) bool {
	l.mu.Lock()
	_, tracked := l.actions[action]
	streams := make([]*logStream, 0, len(l.streams))
	delete(l.actions, action)
	for userID, stream := range l.streams {
		stream.mu.Lock()
		matches := stream.action == action && !stream.stopped
		stream.mu.Unlock()
		if matches {
			delete(l.streams, userID)
			streams = append(streams, stream)
		}
	}
	l.mu.Unlock()
	for _, stream := range streams {
		stream.mu.Lock()
		stream.stopped = true
		stream.cancel()
		if success {
			stream.finalLine = strings.ToUpper(action[:1]) + action[1:] + " completed successfully."
		} else {
			stream.finalLine = strings.ToUpper(action[:1]) + action[1:] + " failed."
		}
		l.finalizeLocked(ctx, stream)
		stream.mu.Unlock()
	}
	return tracked || len(streams) != 0
}

// revokeLocked requires Service.authorizationMu and must be called only after
// access deletion succeeds. It removes output without publishing final text.
func (l *logStreams) revokeLocked(ctx context.Context, userID int64) {
	l.mu.Lock()
	stream, exists := l.streams[userID]
	if !exists {
		l.mu.Unlock()
		return
	}
	delete(l.streams, userID)
	stream.mu.Lock()
	l.mu.Unlock()

	stream.stopped = true
	stream.cancel()
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logBotTimeout)
	l.service.deleteMessages(callCtx, stream.chatID, []int{stream.controlMsgID, stream.outputMsgID}, "live logs")
	cancel()
	stream.mu.Unlock()
}

func (l *logStreams) shutdown() {
	l.mu.Lock()
	if l.stopping {
		l.mu.Unlock()
		return
	}
	l.stopping = true
	for userID, stream := range l.streams {
		delete(l.streams, userID)
		// Cleanup is completed by the owning run goroutine. Shutdown only
		// publishes intent and cancels here, so it never waits for a refresh
		// holding the per-stream mutex.
		stream.deleteOnExit.Store(true)
		stream.cancel()
	}
	clear(l.actions)
	l.mu.Unlock()
}
func (l *logStreams) notify() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopping {
		return
	}
	for _, stream := range l.streams {
		select {
		case stream.updates <- struct{}{}:
		default:
		}
	}
}

// showOlderLocked requires Service.authorizationMu.
func (l *logStreams) showOlderLocked(userID int64) {
	l.mu.Lock()
	stream, exists := l.streams[userID]
	if !exists {
		l.mu.Unlock()
		return
	}
	stream.mu.Lock()
	l.mu.Unlock()
	defer stream.mu.Unlock()
	if stream.stopped || stream.ctx.Err() != nil {
		return
	}
	stream.visibleLines += logPageLines
	stream.current = ""
	select {
	case stream.updates <- struct{}{}:
	default:
	}
}

func visibleLogPage(lines []string, visibleLines int) ([]string, bool) {
	if visibleLines < logPageLines {
		visibleLines = logPageLines
	}
	if len(lines) <= visibleLines {
		return lines, false
	}
	return lines[len(lines)-visibleLines:], true
}

func (l *logStreams) wait(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		l.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *logStreams) run(stream *logStream) {
	defer func() {
		l.mu.Lock()
		if l.streams[stream.userID] == stream {
			delete(l.streams, stream.userID)
		}
		l.mu.Unlock()
		if stream.deleteOnExit.Load() {
			l.cleanupAfterShutdown(stream)
		}
		l.wg.Done()
	}()

	l.refresh(stream)
	ticker := l.newTicker(logRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stream.ctx.Done():
			return
		case <-stream.updates:
			l.refresh(stream)
		case <-ticker.C():
			l.refresh(stream)
		}
	}
}

func (l *logStreams) refresh(stream *logStream) {
	// The access store and stopping flag provide their own synchronization.
	// Never take authorizationMu here: connect/disconnect may hold it while
	// producing logs, and the stream must continue updating in parallel.
	if !l.service.userAllowedLocked(stream.userID) {
		return
	}

	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.stopped || stream.ctx.Err() != nil {
		return
	}

	lines := l.service.controller.Logs()
	if stream.ctx.Err() != nil || stream.stopped {
		return
	}
	lines, hasOlder := visibleLogPage(lines, stream.visibleLines)
	text := formatLogs(lines, false)
	changed := text != stream.current || hasOlder != stream.currentHasOlder
	now := l.service.now()
	if stream.mode == logDeliveryEdit {
		if !changed {
			return
		}
		callCtx, cancel := context.WithTimeout(stream.ctx, logBotTimeout)
		_, err := l.service.bot.EditMessageText(callCtx, &bot.EditMessageTextParams{
			ChatID: stream.chatID, MessageID: stream.outputMsgID, Text: text,
			ParseMode: models.ParseModeHTML, ReplyMarkup: logMarkup(hasOlder),
		})
		cancel()
		if err != nil {
			log.Printf("telegram EditMessageText failed chat=%d error=%T", stream.chatID, err)
			return
		}
		stream.current = text
		stream.currentHasOlder = hasOlder
		return
	}

	if !l.useDrafts {
		l.fallbackLocked(stream, text, hasOlder)
		return
	}
	if !changed && now.Sub(stream.lastDraftAt) < logDraftHeartbeat {
		l.ensureControlLocked(stream, hasOlder)
		return
	}
	callCtx, cancel := context.WithTimeout(stream.ctx, logBotTimeout)
	draftSent, err := l.service.bot.SendMessageDraft(callCtx, &bot.SendMessageDraftParams{
		ChatID: stream.chatID, DraftID: stream.draftID, Text: text, ParseMode: models.ParseModeHTML,
	})
	cancel()
	if err == nil && draftSent {
		if stream.ctx.Err() != nil || stream.stopped {
			return
		}
		stream.current = text
		stream.currentHasOlder = hasOlder
		stream.lastDraftAt = now
		l.ensureControlLocked(stream, hasOlder)
		return
	}
	log.Printf("telegram SendMessageDraft failed chat=%d error=%T", stream.chatID, err)
	if stream.ctx.Err() != nil || stream.stopped {
		return
	}
	l.fallbackLocked(stream, text, hasOlder)
}

func (l *logStreams) ensureControlLocked(stream *logStream, hasOlder bool) {
	if stream.ctx.Err() != nil || stream.stopped {
		return
	}
	const text = "<b>Live logs</b>\nStreaming updates…"
	if stream.controlMsgID != 0 {
		if stream.controlHasOlder == hasOlder {
			return
		}
		callCtx, cancel := context.WithTimeout(stream.ctx, logBotTimeout)
		_, err := l.service.bot.EditMessageText(callCtx, &bot.EditMessageTextParams{
			ChatID: stream.chatID, MessageID: stream.controlMsgID, Text: text,
			ParseMode: models.ParseModeHTML, ReplyMarkup: logMarkup(hasOlder),
		})
		cancel()
		if err != nil {
			log.Printf("telegram EditMessageText failed chat=%d error=%T", stream.chatID, err)
			return
		}
		stream.controlHasOlder = hasOlder
		return
	}
	callCtx, cancel := context.WithTimeout(stream.ctx, logBotTimeout)
	msg, err := l.service.bot.SendMessage(callCtx, &bot.SendMessageParams{
		ChatID: stream.chatID, Text: text, ParseMode: models.ParseModeHTML, ReplyMarkup: logMarkup(hasOlder),
	})
	cancel()
	if err != nil {
		log.Printf("telegram SendMessage failed chat=%d error=%T", stream.chatID, err)
		return
	}
	stream.controlMsgID = msg.ID
	stream.controlHasOlder = hasOlder
}
func (l *logStreams) cleanupAfterShutdown(stream *logStream) {
	stream.mu.Lock()
	messageIDs := []int{stream.controlMsgID, stream.outputMsgID}
	stream.mu.Unlock()

	callCtx, cancel := context.WithTimeout(context.WithoutCancel(stream.ctx), logBotTimeout)
	l.service.deleteMessages(callCtx, stream.chatID, messageIDs, "live logs shutdown")
	cancel()
}

func (l *logStreams) fallbackLocked(stream *logStream, text string, hasOlder bool) {
	if stream.ctx.Err() != nil || stream.stopped {
		return
	}
	callCtx, cancel := context.WithTimeout(stream.ctx, logBotTimeout)
	msg, err := l.service.bot.SendMessage(callCtx, &bot.SendMessageParams{
		ChatID: stream.chatID, Text: text, ParseMode: models.ParseModeHTML, ReplyMarkup: logMarkup(hasOlder),
	})
	cancel()
	if err != nil {
		log.Printf("telegram SendMessage failed chat=%d error=%T", stream.chatID, err)
		return
	}
	stream.mode = logDeliveryEdit
	stream.current = text
	stream.currentHasOlder = hasOlder
	stream.outputMsgID = msg.ID
	if stream.controlMsgID != 0 {
		callCtx, cancel = context.WithTimeout(stream.ctx, logBotTimeout)
		l.service.deleteMessages(callCtx, stream.chatID, []int{stream.controlMsgID}, "live log control")
		cancel()
		stream.controlMsgID = 0
	}
}

func (l *logStreams) finalizeLocked(ctx context.Context, stream *logStream) {
	lines, _ := visibleLogPage(l.service.controller.Logs(), stream.visibleLines)
	if stream.finalLine != "" {
		finalLines := make([]string, len(lines)+1)
		copy(finalLines, lines)
		finalLines[len(lines)] = stream.finalLine
		lines = finalLines
	}
	text := formatLogs(lines, true)
	callCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logBotTimeout)
	defer cancel()
	if stream.mode == logDeliveryEdit && stream.outputMsgID != 0 {
		if _, err := l.service.bot.EditMessageText(callCtx, &bot.EditMessageTextParams{
			ChatID: stream.chatID, MessageID: stream.outputMsgID, Text: text, ParseMode: models.ParseModeHTML,
			ReplyMarkup: &models.InlineKeyboardMarkup{InlineKeyboard: [][]models.InlineKeyboardButton{}},
		}); err != nil {
			log.Printf("telegram EditMessageText failed chat=%d error=%T", stream.chatID, err)
		}
		return
	}
	if _, err := l.service.bot.SendMessage(callCtx, &bot.SendMessageParams{
		ChatID: stream.chatID, Text: text, ParseMode: models.ParseModeHTML,
	}); err != nil {
		log.Printf("telegram SendMessage failed chat=%d error=%T", stream.chatID, err)
	}
	if stream.controlMsgID != 0 {
		l.service.deleteMessages(callCtx, stream.chatID, []int{stream.controlMsgID}, "live log control")
	}
}

func logMarkup(hasOlder bool) *models.InlineKeyboardMarkup {
	rows := make([][]models.InlineKeyboardButton, 0, 2)
	if hasOlder {
		rows = append(rows, []models.InlineKeyboardButton{{Text: "Older logs", CallbackData: "logs:older"}})
	}
	rows = append(rows, []models.InlineKeyboardButton{{Text: "Stop", CallbackData: "logs:stop", Style: "danger"}})
	return &models.InlineKeyboardMarkup{InlineKeyboard: rows}
}

func logStopMarkup() *models.InlineKeyboardMarkup {
	return logMarkup(false)
}

func (s *Service) logs(ctx context.Context, _ *bot.Bot, update *models.Update) {
	if update == nil || update.Message == nil {
		return
	}
	fields := strings.Fields(update.Message.Text)
	if len(fields) == 0 || strings.SplitN(strings.TrimPrefix(fields[0], "/"), "@", 2)[0] != "logs" || len(fields) > 2 {
		return
	}
	action := "start"
	if len(fields) == 2 {
		action = strings.ToLower(fields[1])
		if action != "start" && action != "stop" {
			return
		}
	}

	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chatID, ok := s.allowed(update)
	if !ok {
		return
	}
	_, userID, _ := privateIdentity(update)
	if action == "stop" {
		s.logStreams.stopLocked(ctx, userID, true)
		return
	}
	s.logStreams.startLocked(ctx, chatID, userID)
}

func (s *Service) logsCallback(ctx context.Context, _ *bot.Bot, update *models.Update) {
	if update == nil || update.CallbackQuery == nil {
		return
	}
	s.answerCallback(ctx, update.CallbackQuery.ID)
	data := update.CallbackQuery.Data
	if data != "menu:logs" && data != "logs:stop" && data != "logs:older" {
		return
	}

	s.authorizationMu.Lock()
	defer s.authorizationMu.Unlock()
	chatID, ok := s.allowed(update)
	if !ok {
		return
	}
	_, userID, _ := privateIdentity(update)
	if data == "logs:older" {
		s.logStreams.showOlderLocked(userID)
		return
	}
	if data == "logs:stop" {
		s.logStreams.stopLocked(ctx, userID, true)
		return
	}
	s.logStreams.startLocked(ctx, chatID, userID)
}
