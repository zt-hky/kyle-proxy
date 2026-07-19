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
	chatID int64
	text   string
}

type recordedDelete struct {
	chatID    int64
	messageID int
}

type fakeTelegramClient struct {
	mu          sync.Mutex
	nextID      int
	sends       []recordedSend
	deletes     []recordedDelete
	answers     []string
	answerCh    chan string
	sendHook    func(recordedSend)
	failChat    map[int64]error
	deleteError error
}

func newFakeTelegramClient() *fakeTelegramClient {
	return &fakeTelegramClient{
		nextID:   1000,
		answerCh: make(chan string, 32),
		failChat: make(map[int64]error),
	}
}

func (f *fakeTelegramClient) DeleteWebhook(context.Context, *bot.DeleteWebhookParams) (bool, error) {
	return true, nil
}

func (f *fakeTelegramClient) SetMyCommands(context.Context, *bot.SetMyCommandsParams) (bool, error) {
	return true, nil
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
	record := recordedSend{chatID: numericChatID(params.ChatID), text: params.Text}
	f.sends = append(f.sends, record)
	hook := f.sendHook
	err := f.failChat[numericChatID(params.ChatID)]
	f.mu.Unlock()
	if hook != nil {
		hook(record)
	}
	return &models.Message{ID: id}, err
}

func (f *fakeTelegramClient) DeleteMessage(_ context.Context, params *bot.DeleteMessageParams) (bool, error) {
	f.mu.Lock()
	f.deletes = append(f.deletes, recordedDelete{chatID: numericChatID(params.ChatID), messageID: params.MessageID})
	err := f.deleteError
	f.mu.Unlock()
	return err == nil, err
}

func (f *fakeTelegramClient) AnswerCallbackQuery(_ context.Context, params *bot.AnswerCallbackQueryParams) (bool, error) {
	f.mu.Lock()
	f.answers = append(f.answers, params.CallbackQueryID)
	f.mu.Unlock()
	f.answerCh <- params.CallbackQueryID
	return true, nil
}

func (f *fakeTelegramClient) Start(ctx context.Context) { <-ctx.Done() }

func (f *fakeTelegramClient) snapshotSends() []recordedSend {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedSend(nil), f.sends...)
}

func (f *fakeTelegramClient) snapshotDeletes() []recordedDelete {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedDelete(nil), f.deletes...)
}

func (f *fakeTelegramClient) setSendHook(hook func(recordedSend)) {
	f.mu.Lock()
	f.sendHook = hook
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setDeleteError(err error) {
	f.mu.Lock()
	f.deleteError = err
	f.mu.Unlock()
}

func (f *fakeTelegramClient) setChatFailure(chatID int64, err error) {
	f.mu.Lock()
	f.failChat[chatID] = err
	f.mu.Unlock()
}

type fakeVPNController struct {
	mu                 sync.Mutex
	status             vpn.Status
	savedOTP           bool
	connectCount       int
	connectUsedOTP     []bool
	submitCount        int
	submitUsedOTP      []bool
	disconnectCount    int
	connectError       error
	submitError        error
	disconnectError    error
	connectHook        func()
	submitHook         func()
	eventHandler       func(vpn.Event)
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

func (f *fakeVPNController) OnEvent(fn func(vpn.Event)) {
	f.mu.Lock()
	f.eventHandler = fn
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
	return newService(testOwnerID, store, controller, client), store, controller, client
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
	if deletes := client.snapshotDeletes(); len(deletes) != 2 || deletes[0].messageID != initial.PromptMessageID || deletes[1].messageID != 3 {
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
	if got := len(client.snapshotDeletes()); got != beforeFollowupDeletes+2 {
		t.Fatalf("expired follow-up OTP made %d deletion attempts, want 2", got-beforeFollowupDeletes)
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
	if got := len(client.snapshotDeletes()); got != beforeDeletes+2 {
		t.Fatalf("expired OTP made %d deletion attempts, want 2", got-beforeDeletes)
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
	if got := len(client.snapshotDeletes()); got != 2 {
		t.Fatalf("deletion failures made %d attempts, want 2", got)
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("OTP token appeared in deletion failure logs")
	}
	if !strings.Contains(logs.String(), fmt.Sprintf("message=%d", prompt.PromptMessageID)) || !strings.Contains(logs.String(), "message=2") {
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
	for id := 1; id <= eventCount; id++ {
		name := fmt.Sprintf("event-%03d", id)
		controller.emit(vpn.Event{ID: uint64(id), Kind: vpn.EventKindAction, Name: name, Detail: "queued", Status: vpn.Status{State: vpn.StateConnected}})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.dispatchEvents(ctx)
	sends := waitForSendCount(t, client, eventCount)
	if len(sends) != eventCount {
		t.Fatalf("burst delivered %d events, want %d", len(sends), eventCount)
	}
	for i, send := range sends {
		want := fmt.Sprintf("GlobalProtect · EVENT-%03d\nqueued", i+1)
		if send.chatID != testOwnerID || send.text != want {
			t.Fatalf("burst event[%d] = %#v, want owner text %q", i, send, want)
		}
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
		if send.chatID == testOwnerID && strings.Contains(send.text, "FIRST") {
			firstOnce.Do(func() { close(firstEntered) })
			<-firstRelease
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go service.dispatchEvents(ctx)
	controller.emit(vpn.Event{ID: 1, Kind: vpn.EventKindState, Name: "first", Detail: "one", Status: vpn.Status{State: vpn.StateConnected}})
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

	controller.emit(vpn.Event{ID: 2, Kind: vpn.EventKindAction, Name: "second", Detail: "two", Status: vpn.Status{State: vpn.StateConnected}})
	sends := waitForSendCount(t, client, 5)
	want := []recordedSend{
		{chatID: testOwnerID, text: "GlobalProtect · FIRST\none"},
		{chatID: 200, text: "GlobalProtect · FIRST\none"},
		{chatID: 300, text: "GlobalProtect · FIRST\none"},
		{chatID: testOwnerID, text: "GlobalProtect · SECOND\ntwo"},
		{chatID: 200, text: "GlobalProtect · SECOND\ntwo"},
	}
	if len(sends) != len(want) {
		t.Fatalf("notification attempts = %#v", sends)
	}
	for i := range want {
		if sends[i] != want[i] {
			t.Fatalf("notification[%d] = %#v, want %#v", i, sends[i], want[i])
		}
	}
	if status := controller.Status(); status.State != vpn.StateConnected || status.Detail != "stable" {
		t.Fatalf("notification failure mutated VPN status: %#v", status)
	}

	thirdEntered := make(chan struct{})
	thirdRelease := make(chan struct{})
	var thirdOnce sync.Once
	client.setSendHook(func(send recordedSend) {
		if send.chatID == testOwnerID && strings.Contains(send.text, "THIRD") {
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
	defer flushCancel()
	if err := service.Flush(flushCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush while delivery in flight returned %v", err)
	}
	close(thirdRelease)
	waitForSendCount(t, client, 7)
}
