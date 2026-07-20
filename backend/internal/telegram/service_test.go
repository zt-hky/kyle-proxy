package telegram

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-telegram/bot"
	"github.com/go-telegram/bot/models"
	"globalprotect-manager/internal/control"
	"globalprotect-manager/internal/vpn"
)

const testOwnerID int64 = 100

type recordedSend struct {
	chatID      int64
	text        string
	parseMode   models.ParseMode
	replyMarkup models.ReplyMarkup
	messageID   int
}

type recordedDraft struct {
	chatID    int64
	draftID   string
	text      string
	parseMode models.ParseMode
}

type recordedEdit struct {
	chatID      int64
	messageID   int
	text        string
	parseMode   models.ParseMode
	replyMarkup models.ReplyMarkup
}

type recordedDelete struct {
	chatID     int64
	messageIDs []int
}

type recordedOperation struct {
	method     string
	chatID     int64
	messageID  int
	messageIDs []int
	text       string
}

type fakeTelegramClient struct {
	mu            sync.Mutex
	nextID        int
	sends         []recordedSend
	drafts        []recordedDraft
	edits         []recordedEdit
	deletes       []recordedDelete
	operations    []recordedOperation
	answers       []string
	answerCh      chan string
	sendHook      func(recordedSend)
	draftHook     func(recordedDraft)
	editHook      func(recordedEdit)
	deleteHook    func(recordedDelete)
	failChat      map[int64]error
	draftError    error
	editError     error
	deleteError   error
	webhookError  error
	commandsError error
	commands      []models.BotCommand
	started       chan struct{}
}

func newFakeTelegramClient() *fakeTelegramClient {
	return &fakeTelegramClient{
		nextID:   1000,
		answerCh: make(chan string, 32),
		failChat: make(map[int64]error),
		started:  make(chan struct{}, 1),
	}
}

func (f *fakeTelegramClient) DeleteWebhook(context.Context, *bot.DeleteWebhookParams) (bool, error) {
	return f.webhookError == nil, f.webhookError
}

func (f *fakeTelegramClient) SetMyCommands(_ context.Context, params *bot.SetMyCommandsParams) (bool, error) {
	f.mu.Lock()
	f.commands = append([]models.BotCommand(nil), params.Commands...)
	f.mu.Unlock()
	return f.commandsError == nil, f.commandsError
}

func numericChatID(chatID any) int64 {
	switch value := chatID.(type) {
	case int64:
		return value
	case int:
		return int64(value)
	default:
		panic(fmt.Sprintf("unexpected chat ID type %T", chatID))
	}
}

func (f *fakeTelegramClient) SendMessage(_ context.Context, params *bot.SendMessageParams) (*models.Message, error) {
	f.mu.Lock()
	f.nextID++
	id := f.nextID
	chatID := numericChatID(params.ChatID)
	record := recordedSend{chatID: chatID, text: params.Text, parseMode: params.ParseMode, replyMarkup: params.ReplyMarkup, messageID: id}
	f.sends = append(f.sends, record)
	f.operations = append(f.operations, recordedOperation{method: "send", chatID: chatID, messageID: id, text: params.Text})
	hook := f.sendHook
	err := f.failChat[chatID]
	f.mu.Unlock()
	if hook != nil {
		hook(record)
	}
	return &models.Message{ID: id}, err
}

func (f *fakeTelegramClient) SendMessageDraft(_ context.Context, params *bot.SendMessageDraftParams) (bool, error) {
	f.mu.Lock()
	record := recordedDraft{chatID: numericChatID(params.ChatID), draftID: params.DraftID, text: params.Text, parseMode: params.ParseMode}
	f.drafts = append(f.drafts, record)
	f.operations = append(f.operations, recordedOperation{method: "draft", chatID: record.chatID, text: record.text})
	hook, err := f.draftHook, f.draftError
	f.mu.Unlock()
	if hook != nil {
		hook(record)
	}
	return err == nil, err
}

func (f *fakeTelegramClient) EditMessageText(_ context.Context, params *bot.EditMessageTextParams) (*models.Message, error) {
	f.mu.Lock()
	record := recordedEdit{chatID: numericChatID(params.ChatID), messageID: params.MessageID, text: params.Text, parseMode: params.ParseMode, replyMarkup: params.ReplyMarkup}
	f.edits = append(f.edits, record)
	f.operations = append(f.operations, recordedOperation{method: "edit", chatID: record.chatID, messageID: record.messageID, text: record.text})
	hook, err := f.editHook, f.editError
	f.mu.Unlock()
	if hook != nil {
		hook(record)
	}
	return &models.Message{ID: params.MessageID}, err
}

func (f *fakeTelegramClient) DeleteMessages(_ context.Context, params *bot.DeleteMessagesParams) (bool, error) {
	f.mu.Lock()
	record := recordedDelete{chatID: numericChatID(params.ChatID), messageIDs: append([]int(nil), params.MessageIDs...)}
	f.deletes = append(f.deletes, record)
	f.operations = append(f.operations, recordedOperation{method: "delete", chatID: record.chatID, messageIDs: append([]int(nil), record.messageIDs...)})
	hook, err := f.deleteHook, f.deleteError
	f.mu.Unlock()
	if hook != nil {
		hook(record)
	}
	return err == nil, err
}

func (f *fakeTelegramClient) AnswerCallbackQuery(_ context.Context, params *bot.AnswerCallbackQueryParams) (bool, error) {
	f.mu.Lock()
	f.answers = append(f.answers, params.CallbackQueryID)
	f.operations = append(f.operations, recordedOperation{method: "answer"})
	f.mu.Unlock()
	f.answerCh <- params.CallbackQueryID
	return true, nil
}

func (f *fakeTelegramClient) Start(ctx context.Context) {
	f.started <- struct{}{}
	<-ctx.Done()
}

func (f *fakeTelegramClient) snapshotSends() []recordedSend {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedSend(nil), f.sends...)
}

func (f *fakeTelegramClient) snapshotDrafts() []recordedDraft {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedDraft(nil), f.drafts...)
}

func (f *fakeTelegramClient) snapshotEdits() []recordedEdit {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedEdit(nil), f.edits...)
}

func (f *fakeTelegramClient) snapshotDeletes() []recordedDelete {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedDelete(nil), f.deletes...)
}

func (f *fakeTelegramClient) snapshotOperations() []recordedOperation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedOperation(nil), f.operations...)
}

func (f *fakeTelegramClient) setSendHook(hook func(recordedSend)) {
	f.mu.Lock()
	f.sendHook = hook
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setDraftHook(hook func(recordedDraft)) {
	f.mu.Lock()
	f.draftHook = hook
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setEditHook(hook func(recordedEdit)) {
	f.mu.Lock()
	f.editHook = hook
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setDeleteHook(hook func(recordedDelete)) {
	f.mu.Lock()
	f.deleteHook = hook
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setDeleteError(err error) {
	f.mu.Lock()
	f.deleteError = err
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setDraftError(err error) {
	f.mu.Lock()
	f.draftError = err
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setEditError(err error) {
	f.mu.Lock()
	f.editError = err
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setChatFailure(chatID int64, err error) {
	f.mu.Lock()
	f.failChat[chatID] = err
	f.mu.Unlock()
}

type fakeVPNController struct {
	mu              sync.Mutex
	status          vpn.Status
	logs            []string
	logsCount       int
	savedOTP        bool
	connectCount    int
	connectUsedOTP  []bool
	submitCount     int
	submitUsedOTP   []bool
	disconnectCount int
	connectError    error
	submitError     error
	disconnectError error
	connectHook     func()
	submitHook      func()
	logsHook        func()
	eventHandler    func(vpn.Event)
	logHandler      func()
}

func (f *fakeVPNController) Connect(options control.ConnectOptions) error {
	f.mu.Lock()
	f.connectCount++
	f.connectUsedOTP = append(f.connectUsedOTP, options.OTP != "")
	hook := f.connectHook
	err := f.connectError
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (f *fakeVPNController) SubmitOTP(otp string) error {
	f.mu.Lock()
	f.submitCount++
	f.submitUsedOTP = append(f.submitUsedOTP, otp != "")
	hook := f.submitHook
	err := f.submitError
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return err
}

func (f *fakeVPNController) Disconnect() error {
	f.mu.Lock()
	f.disconnectCount++
	err := f.disconnectError
	f.mu.Unlock()
	return err
}

func (f *fakeVPNController) Status() vpn.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeVPNController) Logs() []string {
	f.mu.Lock()
	f.logsCount++
	lines := append([]string(nil), f.logs...)
	hook := f.logsHook
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return lines
}

func (f *fakeVPNController) OnEvent(fn func(vpn.Event)) {
	f.mu.Lock()
	f.eventHandler = fn
	f.mu.Unlock()
}

func (f *fakeVPNController) OnLog(fn func()) {
	f.mu.Lock()
	f.logHandler = fn
	f.mu.Unlock()
}

func (f *fakeVPNController) HasSavedOTP() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.savedOTP
}

func (f *fakeVPNController) setStatus(status vpn.Status) {
	f.mu.Lock()
	f.status = status
	f.mu.Unlock()
}

func (f *fakeVPNController) setLogs(lines ...string) {
	f.mu.Lock()
	f.logs = append([]string(nil), lines...)
	f.mu.Unlock()
}

func (f *fakeVPNController) emitLogs(lines ...string) {
	f.mu.Lock()
	f.logs = append([]string(nil), lines...)
	handler := f.logHandler
	f.mu.Unlock()
	if handler != nil {
		handler()
	}
}

func (f *fakeVPNController) logCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.logsCount
}

func (f *fakeVPNController) setSavedOTP(saved bool) {
	f.mu.Lock()
	f.savedOTP = saved
	f.mu.Unlock()
}

func (f *fakeVPNController) setConnectHook(hook func()) {
	f.mu.Lock()
	f.connectHook = hook
	f.mu.Unlock()
}

func (f *fakeVPNController) counts() (connect, submit, disconnect int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connectCount, f.submitCount, f.disconnectCount
}

func (f *fakeVPNController) otpUsage() (connect, submit []bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]bool(nil), f.connectUsedOTP...), append([]bool(nil), f.submitUsedOTP...)
}

func (f *fakeVPNController) emit(event vpn.Event) {
	f.mu.Lock()
	fn := f.eventHandler
	f.mu.Unlock()
	fn(event)
}

func newServiceHarness(t *testing.T) (*Service, *AccessStore, *fakeVPNController, *fakeTelegramClient) {
	t.Helper()
	store, err := NewAccessStore(filepath.Join(t.TempDir(), "telegram-access.json"), testOwnerID)
	if err != nil {
		t.Fatalf("create access store: %v", err)
	}
	controller := &fakeVPNController{status: vpn.Status{State: vpn.StateDisconnected}, savedOTP: true}
	client := newFakeTelegramClient()
	service := newService(testOwnerID, store, controller, client)
	service.logStreams.useDrafts = true
	return service, store, controller, client
}

func reloadAccessStore(t *testing.T, store *AccessStore) *AccessStore {
	t.Helper()
	reloaded, err := NewAccessStore(store.path, testOwnerID)
	if err != nil {
		t.Fatalf("reload access store: %v", err)
	}
	return reloaded
}

func accessRecord(id int64, status AccessStatus) AccessRecord {
	requested := time.Now().Add(-time.Minute)
	record := AccessRecord{UserID: id, ChatID: id, Username: fmt.Sprintf("user%d", id), DisplayName: fmt.Sprintf("User %d", id), Status: status, RequestedAt: requested}
	if status != AccessPending {
		decided := requested.Add(time.Second)
		record.DecidedAt = &decided
	}
	return record
}

func mustUpsertAccess(t *testing.T, store *AccessStore, id int64, status AccessStatus) {
	t.Helper()
	if err := store.Upsert(accessRecord(id, status)); err != nil {
		t.Fatalf("upsert access: %v", err)
	}
}

func messageUpdate(userID, chatID int64, chatType models.ChatType, text string, messageID, replyToID int) *models.Update {
	message := &models.Message{
		ID:   messageID,
		From: &models.User{ID: userID, Username: "same-name"},
		Chat: models.Chat{ID: chatID, Type: chatType},
		Text: text,
	}
	if replyToID != 0 {
		message.ReplyToMessage = &models.Message{ID: replyToID}
	}
	return &models.Update{Message: message}
}

func privateMessage(userID int64, text string, messageID, replyToID int) *models.Update {
	return messageUpdate(userID, userID, models.ChatTypePrivate, text, messageID, replyToID)
}

func callbackUpdate(userID, chatID int64, chatType models.ChatType, data, callbackID string) *models.Update {
	return &models.Update{CallbackQuery: &models.CallbackQuery{
		ID:   callbackID,
		From: models.User{ID: userID, Username: "same-name"},
		Message: models.MaybeInaccessibleMessage{
			Type:    models.MaybeInaccessibleMessageTypeMessage,
			Message: &models.Message{Chat: models.Chat{ID: chatID, Type: chatType}},
		},
		Data: data,
	}}
}

func privateCallback(userID int64, data, callbackID string) *models.Update {
	return callbackUpdate(userID, userID, models.ChatTypePrivate, data, callbackID)
}

func waitForAnswer(t *testing.T, client *fakeTelegramClient, id string) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for {
		select {
		case got := <-client.answerCh:
			if got == id {
				return
			}
		case <-deadline.C:
			t.Fatalf("callback %q was not acknowledged", id)
		}
	}
}

func waitForSendCount(t *testing.T, client *fakeTelegramClient, count int) []recordedSend {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		sends := client.snapshotSends()
		if len(sends) >= count {
			return sends
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d sends, want at least %d", len(sends), count)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPrivateChatAuthorizationUsesImmutableUserID(t *testing.T) {
	service, store, _, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	mustUpsertAccess(t, store, 300, AccessPending)
	mustUpsertAccess(t, store, 400, AccessDenied)

	service.status(context.Background(), nil, privateMessage(testOwnerID, "/status", 1, 0))
	service.status(context.Background(), nil, privateMessage(200, "/status", 2, 0))
	service.status(context.Background(), nil, privateMessage(300, "/status", 3, 0))
	service.status(context.Background(), nil, privateMessage(400, "/status", 4, 0))
	service.status(context.Background(), nil, privateMessage(500, "/status", 5, 0))
	service.status(context.Background(), nil, messageUpdate(200, -200, models.ChatTypeGroup, "/status", 6, 0))
	service.status(context.Background(), nil, messageUpdate(200, 200, models.ChatTypeChannel, "/status", 7, 0))

	sends := client.snapshotSends()
	if len(sends) != 2 || sends[0].chatID != testOwnerID || sends[1].chatID != 200 {
		t.Fatalf("authorized sends = %#v, want owner then approved immutable user ID", sends)
	}

	service.BeginShutdown()
	service.status(context.Background(), nil, privateMessage(testOwnerID, "/status", 8, 0))
	if got := len(client.snapshotSends()); got != 2 {
		t.Fatalf("stopping service accepted an action; sends=%d", got)
	}
}

func TestCallbacksAreAcknowledgedButStaleOrStoppedActionsAreRejected(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)

	service.callback(context.Background(), nil, privateCallback(200, "vpn:unknown", "unknown"))
	service.callback(context.Background(), nil, privateCallback(200, "vpn:connect:malformed", "malformed"))
	if connect, submit, disconnect := controller.counts(); connect != 0 || submit != 0 || disconnect != 0 {
		t.Fatalf("unknown callbacks mutated controller: %d/%d/%d", connect, submit, disconnect)
	}

	service.accessCallback(context.Background(), nil, privateCallback(testOwnerID, "access:revoke:200", "revoke"))
	if _, ok := store.Get(200); ok {
		t.Fatal("approved record still exists after revoke")
	}
	service.callback(context.Background(), nil, privateCallback(200, "vpn:connect", "stale"))
	if connect, _, _ := controller.counts(); connect != 0 {
		t.Fatalf("revoked user's stale callback connected %d times", connect)
	}

	service.BeginShutdown()
	service.callback(context.Background(), nil, privateCallback(testOwnerID, "vpn:connect", "stopping"))
	if connect, _, _ := controller.counts(); connect != 0 {
		t.Fatalf("stopping gate allowed owner action; connects=%d", connect)
	}

	for _, id := range []string{"unknown", "malformed", "revoke", "stale", "stopping"} {
		waitForAnswer(t, client, id)
	}
}

func TestAuthorizationSerializesRevokeWithActionAndOTP(t *testing.T) {
	t.Run("controller action begins before revoke", func(t *testing.T) {
		service, store, controller, client := newServiceHarness(t)
		mustUpsertAccess(t, store, 200, AccessApproved)
		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		controller.setConnectHook(func() {
			once.Do(func() { close(entered) })
			<-release
		})

		actionDone := make(chan struct{})
		go func() {
			service.callback(context.Background(), nil, privateCallback(200, "vpn:connect", "connect"))
			close(actionDone)
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("connect did not reach controller")
		}

		revokeDone := make(chan struct{})
		go func() {
			service.accessCallback(context.Background(), nil, privateCallback(testOwnerID, "access:revoke:200", "revoke"))
			close(revokeDone)
		}()
		waitForAnswer(t, client, "revoke")
		if rec, ok := store.Get(200); !ok || rec.Status != AccessApproved {
			t.Fatal("revoke crossed an in-flight authorized controller action")
		}
		select {
		case <-revokeDone:
			t.Fatal("revoke completed before the authorized action released authorizationMu")
		default:
		}

		close(release)
		select {
		case <-actionDone:
		case <-time.After(time.Second):
			t.Fatal("action did not finish")
		}
		select {
		case <-revokeDone:
		case <-time.After(time.Second):
			t.Fatal("revoke did not finish after action")
		}
		if _, ok := store.Get(200); ok {
			t.Fatal("revoke was not persisted")
		}
		service.callback(context.Background(), nil, privateCallback(200, "vpn:connect", "post-revoke"))
		if connect, _, _ := controller.counts(); connect != 1 {
			t.Fatalf("post-revoke stale action changed connect count to %d", connect)
		}
	})

	t.Run("OTP claim begins before revoke", func(t *testing.T) {
		service, store, controller, client := newServiceHarness(t)
		mustUpsertAccess(t, store, 200, AccessApproved)
		controller.setSavedOTP(false)
		service.connect(context.Background(), nil, privateMessage(200, "/connect", 1, 0))
		service.mu.Lock()
		prompt := service.pending[200]
		service.mu.Unlock()

		entered := make(chan struct{})
		release := make(chan struct{})
		var once sync.Once
		controller.setConnectHook(func() {
			once.Do(func() { close(entered) })
			<-release
		})
		otpDone := make(chan struct{})
		go func() {
			service.text(context.Background(), nil, privateMessage(200, strings.Repeat("7", 6), 2, prompt.PromptMessageID))
			close(otpDone)
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("claimed OTP did not reach controller")
		}

		revokeDone := make(chan struct{})
		go func() {
			service.accessCallback(context.Background(), nil, privateCallback(testOwnerID, "access:revoke:200", "otp-revoke"))
			close(revokeDone)
		}()
		waitForAnswer(t, client, "otp-revoke")
		if _, ok := store.Get(200); !ok {
			t.Fatal("revoke crossed an in-flight OTP submission")
		}
		select {
		case <-revokeDone:
			t.Fatal("revoke completed before OTP controller call")
		default:
		}
		close(release)
		select {
		case <-otpDone:
		case <-time.After(time.Second):
			t.Fatal("OTP action did not finish")
		}
		select {
		case <-revokeDone:
		case <-time.After(time.Second):
			t.Fatal("revoke did not finish after OTP action")
		}

		mustUpsertAccess(t, store, 200, AccessApproved)
		service.mu.Lock()
		service.pending[200] = pendingOTP{ChatID: 200, PromptMessageID: 88, Kind: "initial", ExpiresAt: time.Now().Add(time.Minute)}
		service.mu.Unlock()
		service.accessCallback(context.Background(), nil, privateCallback(testOwnerID, "access:revoke:200", "revoke-first"))
		service.text(context.Background(), nil, privateMessage(200, strings.Repeat("8", 6), 3, 88))
		if connect, _, _ := controller.counts(); connect != 1 {
			t.Fatalf("reply after revoke changed connect count to %d", connect)
		}
		service.mu.Lock()
		_, pending := service.pending[200]
		service.mu.Unlock()
		if pending {
			t.Fatal("revoke did not cancel pending OTP")
		}
	})
}

func TestOTPReplyMustMatchPromptExpiresAndIsClaimedOnce(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	controller.setSavedOTP(false)
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }

	service.connect(context.Background(), nil, privateMessage(200, "/connect", 1, 0))
	service.mu.Lock()
	initial := service.pending[200]
	service.mu.Unlock()
	service.text(context.Background(), nil, privateMessage(200, "not-an-otp", 2, initial.PromptMessageID+1))
	if connect, _, _ := controller.counts(); connect != 0 {
		t.Fatalf("reply to wrong prompt connected %d times", connect)
	}
	if got := len(client.snapshotDeletes()); got != 0 {
		t.Fatalf("wrong reply caused %d deletions", got)
	}
	service.mu.Lock()
	_, stillPending := service.pending[200]
	service.mu.Unlock()
	if !stillPending {
		t.Fatal("wrong reply consumed the pending prompt")
	}

	service.text(context.Background(), nil, privateMessage(200, strings.Repeat("3", 6), 3, initial.PromptMessageID))
	service.text(context.Background(), nil, privateMessage(200, strings.Repeat("3", 6), 3, initial.PromptMessageID))
	if connect, _, _ := controller.counts(); connect != 1 {
		t.Fatalf("one-time initial prompt connected %d times", connect)
	}
	if deletes := client.snapshotDeletes(); len(deletes) != 1 || len(deletes[0].messageIDs) != 2 || deletes[0].messageIDs[0] != initial.PromptMessageID || deletes[0].messageIDs[1] != 3 {
		t.Fatalf("initial OTP deletion attempts = %#v", deletes)
	}
	connectOTP, _ := controller.otpUsage()
	if len(connectOTP) != 1 || !connectOTP[0] {
		t.Fatal("initial OTP was not forwarded without retaining its value in the test")
	}

	controller.setStatus(vpn.Status{State: vpn.StateConnecting, AwaitingOTP: true})
	service.callback(context.Background(), nil, privateCallback(200, "vpn:otp", "followup"))
	service.mu.Lock()
	followup := service.pending[200]
	service.mu.Unlock()
	service.text(context.Background(), nil, privateMessage(200, strings.Repeat("4", 6), 4, followup.PromptMessageID))
	service.text(context.Background(), nil, privateMessage(200, strings.Repeat("4", 6), 4, followup.PromptMessageID))
	if _, submit, _ := controller.counts(); submit != 1 {
		t.Fatalf("follow-up prompt submitted %d times", submit)
	}
	_, submitOTP := controller.otpUsage()
	if len(submitOTP) != 1 || !submitOTP[0] {
		t.Fatal("follow-up OTP was not forwarded")
	}
	service.callback(context.Background(), nil, privateCallback(200, "vpn:otp", "expired-followup"))
	service.mu.Lock()
	expiredFollowup := service.pending[200]
	service.mu.Unlock()
	now = now.Add(121 * time.Second)
	beforeFollowupDeletes := len(client.snapshotDeletes())
	service.text(context.Background(), nil, privateMessage(200, strings.Repeat("5", 6), 5, expiredFollowup.PromptMessageID))
	if _, submit, _ := controller.counts(); submit != 1 {
		t.Fatalf("expired follow-up OTP reached controller; submit count=%d", submit)
	}
	if got := len(client.snapshotDeletes()); got != beforeFollowupDeletes+1 {
		t.Fatalf("expired follow-up OTP made %d deletion requests, want 1", got-beforeFollowupDeletes)
	}

	controller.setStatus(vpn.Status{State: vpn.StateDisconnected})
	service.connect(context.Background(), nil, privateMessage(200, "/connect", 6, 0))
	service.mu.Lock()
	expired := service.pending[200]
	service.mu.Unlock()
	now = now.Add(121 * time.Second)
	// The expiration clock is advanced after each prompt is created.
	beforeDeletes := len(client.snapshotDeletes())
	service.text(context.Background(), nil, privateMessage(200, strings.Repeat("6", 6), 7, expired.PromptMessageID))
	if connect, _, _ := controller.counts(); connect != 1 {
		t.Fatalf("expired OTP reached controller; connect count=%d", connect)
	}
	if got := len(client.snapshotDeletes()); got != beforeDeletes+1 {
		t.Fatalf("expired OTP made %d deletion requests, want 1", got-beforeDeletes)
	}
}

func TestOTPDeletionFailuresNeverLogToken(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	controller.setSavedOTP(false)
	service.connect(context.Background(), nil, privateMessage(200, "/connect", 1, 0))
	service.mu.Lock()
	prompt := service.pending[200]
	service.mu.Unlock()

	token := strings.Repeat("9", 7)
	client.setDeleteError(errors.New("adapter echoed " + token))
	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)

	service.text(context.Background(), nil, privateMessage(200, token, 2, prompt.PromptMessageID))
	if got := len(client.snapshotDeletes()); got != 1 {
		t.Fatalf("deletion failures made %d requests, want 1", got)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("OTP token appeared in deletion failure logs")
	}
	if !strings.Contains(logs.String(), fmt.Sprintf("messages=[%d 2]", prompt.PromptMessageID)) {
		t.Fatalf("deletion logs omitted message IDs: %q", logs.String())
	}
}

func TestAccessRequestDecisionAndRevokePersistence(t *testing.T) {
	service, store, _, client := newServiceHarness(t)
	ctx := context.Background()

	service.start(ctx, nil, privateMessage(200, "/start", 1, 0))
	record, ok := store.Get(200)
	if !ok || record.Status != AccessPending || record.UserID != 200 || record.ChatID != 200 {
		t.Fatalf("persisted request = %#v, %v", record, ok)
	}
	ownerCards := 0
	for _, send := range client.snapshotSends() {
		if send.chatID == testOwnerID && strings.Contains(send.text, "Access request") {
			ownerCards++
		}
	}
	service.start(ctx, nil, privateMessage(200, "/start", 2, 0))
	for _, send := range client.snapshotSends()[2:] {
		if send.chatID == testOwnerID && strings.Contains(send.text, "Access request") {
			ownerCards++
		}
	}
	if ownerCards != 1 {
		t.Fatalf("repeated pending /start generated %d owner cards", ownerCards)
	}

	service.accessCallback(ctx, nil, privateCallback(testOwnerID, "access:approve:200", "approve"))
	record, ok = store.Get(200)
	if !ok || record.Status != AccessApproved || record.DecidedAt == nil {
		t.Fatalf("approved record = %#v, %v", record, ok)
	}
	if persisted, exists := reloadAccessStore(t, store).Get(200); !exists || persisted.Status != AccessApproved {
		t.Fatalf("approved decision was not durable: %#v, %v", persisted, exists)
	}
	beforeStale := len(client.snapshotSends())
	service.accessCallback(ctx, nil, privateCallback(testOwnerID, "access:deny:200", "stale-deny"))
	record, _ = store.Get(200)
	if record.Status != AccessApproved || len(client.snapshotSends()) != beforeStale {
		t.Fatal("stale deny callback changed approved access")
	}

	service.start(ctx, nil, privateMessage(300, "/start", 3, 0))
	service.accessCallback(ctx, nil, privateCallback(testOwnerID, "access:deny:300", "deny"))
	denied, ok := store.Get(300)
	if !ok || denied.Status != AccessDenied || denied.DecidedAt == nil {
		t.Fatalf("denied record = %#v, %v", denied, ok)
	}
	if persisted, exists := reloadAccessStore(t, store).Get(300); !exists || persisted.Status != AccessDenied {
		t.Fatalf("denied decision was not durable: %#v, %v", persisted, exists)
	}
	service.start(ctx, nil, privateMessage(300, "/start", 4, 0))
	deniedAgain, _ := store.Get(300)
	if deniedAgain.Status != AccessDenied || !deniedAgain.RequestedAt.Equal(denied.RequestedAt) {
		t.Fatal("denied /start reset the decision")
	}

	service.mu.Lock()
	service.pending[200] = pendingOTP{ChatID: 200, PromptMessageID: 44, Kind: "followup", ExpiresAt: time.Now().Add(time.Minute)}
	service.mu.Unlock()
	service.accessCallback(ctx, nil, privateCallback(testOwnerID, "access:revoke:200", "revoke"))
	if _, ok := store.Get(200); ok {
		t.Fatal("revoke did not persist deletion")
	}
	if _, exists := reloadAccessStore(t, store).Get(200); exists {
		t.Fatal("revoked record remained in persisted access file")
	}
	service.mu.Lock()
	_, pending := service.pending[200]
	service.mu.Unlock()
	if pending {
		t.Fatal("successful revoke retained pending OTP")
	}
}

func TestAccessPersistenceFailurePreservesAuthorizationAndPendingOTP(t *testing.T) {
	service, store, _, client := newServiceHarness(t)
	ctx := context.Background()
	mustUpsertAccess(t, store, 200, AccessPending)
	validPath := store.path
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("create persistence blocker: %v", err)
	}
	store.path = filepath.Join(blocker, "access.json")

	before := len(client.snapshotSends())
	service.accessCallback(ctx, nil, privateCallback(testOwnerID, "access:approve:200", "failed-approve"))
	record, ok := store.Get(200)
	if !ok || record.Status != AccessPending || record.DecidedAt != nil {
		t.Fatalf("failed approve changed in-memory access: %#v, %v", record, ok)
	}
	if len(client.snapshotSends()) != before {
		t.Fatal("user was notified before failed approve persisted")
	}

	store.path = validPath
	service.accessCallback(ctx, nil, privateCallback(testOwnerID, "access:approve:200", "approve"))
	service.mu.Lock()
	service.pending[200] = pendingOTP{ChatID: 200, PromptMessageID: 77, Kind: "initial", ExpiresAt: time.Now().Add(time.Minute)}
	service.mu.Unlock()
	store.path = filepath.Join(blocker, "access.json")
	service.accessCallback(ctx, nil, privateCallback(testOwnerID, "access:revoke:200", "failed-revoke"))
	record, ok = store.Get(200)
	if !ok || record.Status != AccessApproved {
		t.Fatalf("failed revoke changed authorization: %#v, %v", record, ok)
	}
	service.mu.Lock()
	_, pending := service.pending[200]
	service.mu.Unlock()
	if !pending {
		t.Fatal("failed revoke canceled pending OTP before persistence")
	}
}

func TestEventFIFODoesNotDropBurst(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	const eventCount = 130
	events := make([]vpn.Event, 0, eventCount)
	for id := 1; id <= eventCount; id++ {
		event := vpn.Event{ID: uint64(id), Kind: vpn.EventKindAction, Name: fmt.Sprintf("event-%03d", id), Detail: "queued", Status: vpn.Status{State: vpn.StateConnected}}
		events = append(events, event)
		controller.emit(event)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.dispatchEvents(ctx)
	edits := waitForEditCount(t, client, eventCount-1)
	sends := client.snapshotSends()
	if len(sends) != 1 {
		t.Fatalf("burst created %d messages, want one", len(sends))
	}
	if len(edits) != eventCount-1 {
		t.Fatalf("burst produced %d edits, want %d", len(edits), eventCount-1)
	}
	last := edits[len(edits)-1]
	want := formatEvents(events[eventCount-eventStreamMaxEvents:], false)
	if sends[0].chatID != testOwnerID || sends[0].parseMode != models.ParseModeHTML {
		t.Fatalf("burst send = %#v, want owner HTML message", sends[0])
	}
	if last.chatID != testOwnerID || last.messageID != sends[0].messageID || last.text != want || last.parseMode != models.ParseModeHTML {
		t.Fatalf("last burst edit = %#v, want original message %d with capped event stream", last, sends[0].messageID)
	}

	flushCtx, flushCancel := context.WithTimeout(context.Background(), time.Second)
	defer flushCancel()
	if err := service.Flush(flushCtx); err != nil {
		t.Fatalf("flush completed burst: %v", err)
	}
}

func TestEventFIFOUsesDequeueRecipientSnapshotAndContinuesAfterSendFailure(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	mustUpsertAccess(t, store, 300, AccessApproved)
	// The loader forbids owner records. Injecting one here exercises the service's
	// defensive recipient deduplication independently of loader validation.
	store.mu.Lock()
	store.users[testOwnerID] = accessRecord(testOwnerID, AccessApproved)
	store.mu.Unlock()
	controller.setStatus(vpn.Status{State: vpn.StateConnected, Detail: "stable"})
	client.setChatFailure(200, errors.New("recipient blocked bot"))

	firstEntered := make(chan struct{})
	firstRelease := make(chan struct{})
	var firstOnce sync.Once
	client.setSendHook(func(send recordedSend) {
		if send.chatID == testOwnerID && strings.Contains(send.text, "first") {
			firstOnce.Do(func() { close(firstEntered) })
			<-firstRelease
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.dispatchEvents(ctx)
	first := vpn.Event{ID: 1, Kind: vpn.EventKindState, Name: "first", Detail: "one", Status: vpn.Status{State: vpn.StateConnected}}
	controller.emit(first)
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first notification did not begin")
	}
	if err := store.Delete(300); err != nil {
		t.Fatalf("revoke recipient during delivery: %v", err)
	}
	close(firstRelease)
	waitForSendCount(t, client, 3)

	second := vpn.Event{ID: 2, Kind: vpn.EventKindAction, Name: "second", Detail: "two", Status: vpn.Status{State: vpn.StateConnected}}
	controller.emit(second)
	waitForOperationCount(t, client, "edit", 1)
	sends := waitForSendCount(t, client, 4)
	wantChats := []int64{testOwnerID, 200, 300, 200}
	for i, chatID := range wantChats {
		if sends[i].chatID != chatID || sends[i].parseMode != models.ParseModeHTML {
			t.Fatalf("notification send[%d] = %#v, want chat %d HTML", i, sends[i], chatID)
		}
	}
	ownerEdit := client.snapshotEdits()[0]
	if ownerEdit.chatID != testOwnerID || ownerEdit.messageID != sends[0].messageID || ownerEdit.text != formatEvents([]vpn.Event{first, second}, false) {
		t.Fatalf("owner aggregation edit = %#v", ownerEdit)
	}
	if status := controller.Status(); status.State != vpn.StateConnected || status.Detail != "stable" {
		t.Fatalf("notification failure mutated VPN status: %#v", status)
	}

	thirdEntered := make(chan struct{})
	thirdRelease := make(chan struct{})
	var thirdOnce sync.Once
	client.setEditHook(func(edit recordedEdit) {
		if edit.chatID == testOwnerID && strings.Contains(edit.text, "third") {
			thirdOnce.Do(func() { close(thirdEntered) })
			<-thirdRelease
		}
	})
	controller.emit(vpn.Event{ID: 3, Kind: vpn.EventKindPhase, Name: "third", Detail: "three", Status: vpn.Status{State: vpn.StateConnected}})
	select {
	case <-thirdEntered:
	case <-time.After(time.Second):
		t.Fatal("third notification did not begin")
	}
	flushCtx, flushCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	if err := service.Flush(flushCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush while delivery in flight returned %v", err)
	}
	flushCancel()
	close(thirdRelease)
	waitForSendCount(t, client, 5)

	finalCtx, finalCancel := context.WithTimeout(context.Background(), time.Second)
	defer finalCancel()
	if err := service.Flush(finalCtx); err != nil {
		t.Fatalf("final flush: %v", err)
	}
}

func TestStartSetupFailuresAndSuccess(t *testing.T) {
	for _, tc := range []struct {
		name     string
		webhook  error
		commands error
		starts   bool
	}{
		{name: "webhook failure", webhook: errors.New("webhook")},
		{name: "command failure", commands: errors.New("commands")},
		{name: "success", starts: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, _, _, client := newServiceHarness(t)
			client.webhookError = tc.webhook
			client.commandsError = tc.commands
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				service.Start(ctx)
				close(done)
			}()
			if tc.starts {
				select {
				case <-client.started:
				case <-time.After(time.Second):
					t.Fatal("bot did not start")
				}
				cancel()
			} else {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("setup failure did not return")
				}
				cancel()
			}
			<-done
		})
	}
}

func TestCommandsMenusAndControllerFailures(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	ctx := context.Background()
	mustUpsertAccess(t, store, 200, AccessApproved)

	service.menu(ctx, nil, privateMessage(200, "/menu", 1, 0))
	service.accessCommand(ctx, nil, privateMessage(200, "/access", 2, 0))
	service.accessCommand(ctx, nil, privateMessage(testOwnerID, "/access", 3, 0))
	controller.connectError = errors.New("connect broke")
	service.connect(ctx, nil, privateMessage(200, "/connect", 4, 0))
	controller.disconnectError = errors.New("disconnect broke")
	service.disconnect(ctx, nil, privateMessage(200, "/disconnect", 5, 0))
	controller.disconnectError = nil
	service.callback(ctx, nil, privateCallback(200, "vpn:disconnect", "disconnect"))
	service.callback(ctx, nil, privateCallback(200, "menu:main", "main"))

	texts := make([]string, 0)
	for _, send := range client.snapshotSends() {
		texts = append(texts, send.text)
	}
	joined := strings.Join(texts, "\n")
	for _, want := range []string{"<b>Telegram access</b>", "Connect failed.", "Disconnect failed."} {
		if !strings.Contains(joined, want) {
			t.Fatalf("messages %q omit %q", joined, want)
		}
	}

	for _, status := range []vpn.Status{
		{State: vpn.StateDisconnected},
		{State: vpn.StateError},
		{State: vpn.StateConnecting},
		{State: vpn.StateConnecting, AwaitingOTP: true},
		{State: vpn.StateConnected},
	} {
		controller.setStatus(status)
		service.sendMenu(ctx, testOwnerID)
	}
}

func TestStartIdentityAndAccessCallbackValidation(t *testing.T) {
	service, store, _, client := newServiceHarness(t)
	ctx := context.Background()
	service.start(ctx, nil, nil)
	service.start(ctx, nil, messageUpdate(200, -1, models.ChatTypeGroup, "/start", 1, 0))
	service.start(ctx, nil, privateMessage(testOwnerID, "/start", 2, 0))
	mustUpsertAccess(t, store, 200, AccessApproved)
	service.start(ctx, nil, privateMessage(200, "/start", 3, 0))
	service.accessCallback(ctx, nil, nil)
	service.accessCallback(ctx, nil, privateCallback(200, "access:deny:200", "not-owner"))
	for i, data := range []string{
		"access:approve",
		"access:approve:nope",
		"access:approve:100",
		"access:approve:999",
		"access:unknown:200",
		"access:approve:200",
		"access:revoke:999",
	} {
		service.accessCallback(ctx, nil, privateCallback(testOwnerID, data, fmt.Sprintf("validation-%d", i)))
	}
	if len(client.snapshotSends()) == 0 {
		t.Fatal("owner and approved start should send menus")
	}
}

func TestOTPPromptAndSubmissionErrors(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	ctx := context.Background()
	mustUpsertAccess(t, store, 200, AccessApproved)

	controller.setStatus(vpn.Status{State: vpn.StateDisconnected})
	service.otpPrompt(ctx, nil, privateMessage(200, "/otp", 1, 0))
	service.otpPromptLocked(ctx, 200, 200)
	client.setChatFailure(200, errors.New("send failed"))
	controller.setStatus(vpn.Status{State: vpn.StateConnecting, AwaitingOTP: true})
	service.otpPrompt(ctx, nil, privateMessage(200, "/otp", 2, 0))
	client.setChatFailure(200, nil)
	service.otpPrompt(ctx, nil, privateMessage(200, "/otp", 3, 0))
	service.mu.Lock()
	prompt := service.pending[200]
	service.mu.Unlock()
	controller.submitError = errors.New("submit broke")
	service.text(ctx, nil, privateMessage(200, "123456", 4, prompt.PromptMessageID))

	controller.setSavedOTP(false)
	service.connect(ctx, nil, privateMessage(200, "/connect", 5, 0))
	service.mu.Lock()
	initial := service.pending[200]
	service.mu.Unlock()
	controller.connectError = errors.New("initial broke")
	service.text(ctx, nil, privateMessage(200, "654321", 6, initial.PromptMessageID))

	joined := ""
	for _, send := range client.snapshotSends() {
		joined += send.text + "\n"
	}
	if strings.Count(joined, formatOTPError()) < 1 || !strings.Contains(joined, "Connect failed.") {
		t.Fatalf("OTP failures not reported in generic message and action stream: %q", joined)
	}
	if strings.Contains(joined, "submit broke") || strings.Contains(joined, "initial broke") {
		t.Fatalf("OTP adapter errors leaked to users: %q", joined)
	}
}

func TestNotifyPromptInvalidationAndFlushWithoutDispatcher(t *testing.T) {
	service, _, controller, _ := newServiceHarness(t)
	service.mu.Lock()
	service.pending[200] = pendingOTP{Kind: "followup"}
	service.pending[300] = pendingOTP{Kind: "initial"}
	service.mu.Unlock()
	controller.emit(vpn.Event{Kind: vpn.EventKindState, Status: vpn.Status{AwaitingOTP: false}})
	service.mu.Lock()
	if len(service.pending) != 0 {
		t.Fatalf("state event retained prompts: %#v", service.pending)
	}
	service.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.Flush(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Flush without dispatcher = %v, want canceled", err)
	}
	controller.emit(vpn.Event{Kind: vpn.EventKindAction})
	service.eventMu.Lock()
	defer service.eventMu.Unlock()
	if len(service.events) != 1 {
		t.Fatalf("notification appended after stopping: %d", len(service.events))
	}
}

func TestPrivateIdentityMalformedCallbackAndDisplayName(t *testing.T) {
	if _, _, ok := privateIdentity(nil); ok {
		t.Fatal("nil update has an identity")
	}
	if _, _, ok := privateIdentity(&models.Update{CallbackQuery: &models.CallbackQuery{}}); ok {
		t.Fatal("inaccessible callback has an identity")
	}
	if got := displayName(&models.User{FirstName: "First", LastName: "Last"}); got != "First Last" {
		t.Fatalf("displayName = %q", got)
	}
	if got := displayName(&models.User{Username: "fallback"}); got != "fallback" {
		t.Fatalf("fallback displayName = %q", got)
	}
}

func TestNewRejectsAccessStoreFailure(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "directory")
	if err := os.Mkdir(blocker, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := New("unused", testOwnerID, blocker, nil); err == nil {
		t.Fatal("New accepted an unreadable access-store path")
	}
}
