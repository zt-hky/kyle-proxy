package telegram

import (
	"context"
	"errors"
	"html"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-telegram/bot/models"
	"globalprotect-manager/internal/vpn"
)

type fakeLogTicker struct {
	ch          chan time.Time
	stopEntered chan struct{}
	stopRelease <-chan struct{}
	stopOnce    sync.Once
}

func newFakeLogTicker(stopRelease <-chan struct{}) *fakeLogTicker {
	return &fakeLogTicker{
		ch:          make(chan time.Time, 8),
		stopEntered: make(chan struct{}),
		stopRelease: stopRelease,
	}
}

func (t *fakeLogTicker) C() <-chan time.Time { return t.ch }

func (t *fakeLogTicker) Stop() {
	t.stopOnce.Do(func() {
		close(t.stopEntered)
		if t.stopRelease != nil {
			<-t.stopRelease
		}
	})
}

type fakeLogTickerFactory struct {
	mu          sync.Mutex
	tickers     []*fakeLogTicker
	created     chan *fakeLogTicker
	stopRelease <-chan struct{}
}

func newFakeLogTickerFactory(stopRelease <-chan struct{}) *fakeLogTickerFactory {
	return &fakeLogTickerFactory{created: make(chan *fakeLogTicker, 8), stopRelease: stopRelease}
}

func (f *fakeLogTickerFactory) New(_ time.Duration) logTicker {
	ticker := newFakeLogTicker(f.stopRelease)
	f.mu.Lock()
	f.tickers = append(f.tickers, ticker)
	f.mu.Unlock()
	f.created <- ticker
	return ticker
}

func (f *fakeLogTickerFactory) wait(t *testing.T) *fakeLogTicker {
	t.Helper()
	select {
	case ticker := <-f.created:
		return ticker
	case <-time.After(time.Second):
		t.Fatal("log ticker was not created")
		return nil
	}
}

type fakeLogClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeLogClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeLogClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func waitForLogCondition(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForDraftCount(t *testing.T, client *fakeTelegramClient, count int) []recordedDraft {
	t.Helper()
	waitForLogCondition(t, "draft delivery", func() bool { return len(client.snapshotDrafts()) >= count })
	return client.snapshotDrafts()
}

func waitForEditCount(t *testing.T, client *fakeTelegramClient, count int) []recordedEdit {
	t.Helper()
	waitForLogCondition(t, "edited delivery", func() bool { return len(client.snapshotEdits()) >= count })
	return client.snapshotEdits()
}

func waitForLogCalls(t *testing.T, controller *fakeVPNController, count int) {
	t.Helper()
	waitForLogCondition(t, "controller log snapshot", func() bool { return controller.logCallCount() >= count })
}

func stopLogService(t *testing.T, service *Service) {
	t.Helper()
	service.BeginShutdown()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.logStreams.wait(ctx); err != nil {
		t.Fatalf("wait for log streams: %v", err)
	}
}

func TestLogStreamUsesOnePersistentMessage(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	controller.setLogs("first")
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	ticker := factory.wait(t)
	first := waitForSendCount(t, client, 1)[0]
	if drafts := client.snapshotDrafts(); len(drafts) != 0 {
		t.Fatalf("draft deliveries = %d, want none", len(drafts))
	}
	requireLogStopMarkup(t, first.replyMarkup)

	controller.setLogs("second")
	ticker.ch <- time.Now()
	edits := waitForEditCount(t, client, 1)
	if edits[0].messageID != first.messageID {
		t.Fatalf("first edit message = %d, want original message %d", edits[0].messageID, first.messageID)
	}

	controller.setLogs("third")
	ticker.ch <- time.Now()
	edits = waitForEditCount(t, client, 2)
	if edits[1].messageID != first.messageID {
		t.Fatalf("second edit message = %d, want original message %d", edits[1].messageID, first.messageID)
	}
	if sends := client.snapshotSends(); len(sends) != 1 {
		t.Fatalf("stream messages = %d, want exactly one", len(sends))
	}

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs stop", 2, 0))
	waitForEditCount(t, client, 3)
	stopLogService(t, service)
}

func TestLogStreamPaginatesOlderLinesInPlace(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	lines := make([]string, 45)
	for i := range lines {
		lines[i] = "line " + strconv.Itoa(i+1)
	}
	controller.setLogs(lines...)
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	factory.wait(t)
	initial := waitForSendCount(t, client, 1)[0]
	if initial.text != formatLogs(lines[25:], false) {
		t.Fatalf("initial page = %q, want last 20 lines", initial.text)
	}
	requireOlderLogsButton(t, initial.replyMarkup, true)

	service.logsCallback(context.Background(), nil, privateCallback(testOwnerID, "logs:older", "older-1"))
	edits := waitForEditCount(t, client, 1)
	if edits[0].messageID != initial.messageID || edits[0].text != formatLogs(lines[5:], false) {
		t.Fatalf("first older page = %#v, want last 40 lines on message %d", edits[0], initial.messageID)
	}
	requireOlderLogsButton(t, edits[0].replyMarkup, true)

	service.logsCallback(context.Background(), nil, privateCallback(testOwnerID, "logs:older", "older-2"))
	edits = waitForEditCount(t, client, 2)
	if edits[1].messageID != initial.messageID || edits[1].text != formatLogs(lines, false) {
		t.Fatalf("second older page = %#v, want all lines on message %d", edits[1], initial.messageID)
	}
	requireOlderLogsButton(t, edits[1].replyMarkup, false)
	requireLogStopMarkup(t, edits[1].replyMarkup)

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs stop", 2, 0))
	waitForEditCount(t, client, 3)
	stopLogService(t, service)
}

func TestCompletedActionKeepsFinalLogPageBounded(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	controller.setSavedOTP(true)
	lines := make([]string, 45)
	for i := range lines {
		lines[i] = "action line " + strconv.Itoa(i+1)
	}
	controller.setLogs(lines...)

	service.connect(context.Background(), nil, privateMessage(testOwnerID, "/connect", 1, 0))
	initial := waitForSendCount(t, client, 1)[0]
	controller.emit(vpn.Event{Kind: vpn.EventKindState, Name: string(vpn.StateConnected), Status: vpn.Status{State: vpn.StateConnected}})
	final := waitForEditCount(t, client, 1)[0]

	wantLines := make([]string, logPageLines+1)
	copy(wantLines, lines[len(lines)-logPageLines:])
	wantLines[logPageLines] = "Connect completed successfully."
	if final.messageID != initial.messageID || final.text != formatLogs(wantLines, true) {
		t.Fatalf("final action page = %#v, want bounded completion on message %d", final, initial.messageID)
	}
	requireNoLogKeyboard(t, final.replyMarkup)
	stopLogService(t, service)
}

func TestLogSignalUpdatesImmediatelyWithoutBlockingActions(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	controller.setLogs("old")
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	factory.wait(t)
	waitForSendCount(t, client, 1)

	editEntered := make(chan struct{})
	editRelease := make(chan struct{})
	var once sync.Once
	client.setEditHook(func(recordedEdit) {
		once.Do(func() {
			close(editEntered)
			<-editRelease
		})
	})
	controller.emitLogs("old", "new")
	select {
	case <-editEntered:
	case <-time.After(time.Second):
		t.Fatal("new log did not trigger an immediate edit")
	}

	actionDone := make(chan struct{})
	go func() {
		service.status(context.Background(), nil, privateMessage(testOwnerID, "/status", 2, 0))
		close(actionDone)
	}()
	select {
	case <-actionDone:
	case <-time.After(100 * time.Millisecond):
		close(editRelease)
		t.Fatal("VPN action was blocked by the in-flight log edit")
	}
	close(editRelease)
	waitForEditCount(t, client, 1)
	stopLogService(t, service)
}

func TestConnectActionStreamsLogsAndAutoStopsOnTerminalEvent(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	controller.setSavedOTP(true)
	controller.setLogs("before connect")

	service.connect(context.Background(), nil, privateMessage(testOwnerID, "/connect", 1, 0))
	first := waitForSendCount(t, client, 1)[0]
	controller.emitLogs("before connect", "connecting")
	waitForEditCount(t, client, 1)
	controller.emit(vpn.Event{Kind: vpn.EventKindPhase, Name: "auth", Status: vpn.Status{State: vpn.StateConnecting}})
	controller.emitLogs("before connect", "connecting", "tunnel ready")
	waitForEditCount(t, client, 2)
	controller.emit(vpn.Event{Kind: vpn.EventKindState, Name: string(vpn.StateConnected), Status: vpn.Status{State: vpn.StateConnected}})
	edits := waitForEditCount(t, client, 3)

	if edits[2].messageID != first.messageID || !strings.Contains(edits[2].text, "Connect completed successfully.") {
		t.Fatalf("terminal edit = %#v, want successful completion on original message %d", edits[2], first.messageID)
	}
	requireNoLogKeyboard(t, edits[2].replyMarkup)
	service.eventMu.Lock()
	queuedEvents := len(service.events)
	service.eventMu.Unlock()
	if queuedEvents != 0 {
		t.Fatalf("action lifecycle notifications queued = %d, want none", queuedEvents)
	}
	stopLogService(t, service)
}

func TestDisconnectActionUsesOneFinalLogMessage(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	controller.setLogs("connected")

	service.disconnect(context.Background(), nil, privateMessage(testOwnerID, "/disconnect", 1, 0))
	sends := waitForSendCount(t, client, 1)
	if len(sends) != 1 || !strings.Contains(sends[0].text, "Disconnect completed successfully.") {
		t.Fatalf("disconnect stream sends = %#v, want one completed log message", sends)
	}
	if drafts := client.snapshotDrafts(); len(drafts) != 0 {
		t.Fatalf("disconnect drafts = %d, want none", len(drafts))
	}
	stopLogService(t, service)
}

func TestStopButtonEndsActionStreamButKeepsLifecycleMessagesSuppressed(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	controller.setSavedOTP(true)
	controller.setLogs("connecting")

	service.connect(context.Background(), nil, privateMessage(testOwnerID, "/connect", 1, 0))
	waitForSendCount(t, client, 1)
	service.logsCallback(context.Background(), nil, privateCallback(testOwnerID, "logs:stop", "stop"))
	waitForEditCount(t, client, 1)
	controller.emit(vpn.Event{Kind: vpn.EventKindPhase, Name: "auth", Status: vpn.Status{State: vpn.StateConnecting}})
	controller.emit(vpn.Event{Kind: vpn.EventKindState, Name: string(vpn.StateConnected), Status: vpn.Status{State: vpn.StateConnected}})

	service.eventMu.Lock()
	queuedEvents := len(service.events)
	service.eventMu.Unlock()
	if queuedEvents != 0 {
		t.Fatalf("events queued after user stopped action stream = %d, want none", queuedEvents)
	}
	if sends := client.snapshotSends(); len(sends) != 1 {
		t.Fatalf("messages after stop = %d, want original stream only", len(sends))
	}
	stopLogService(t, service)
}

func TestLogsAuthorizeOnlyOwnerAndApprovedPrivateUsers(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	mustUpsertAccess(t, store, 300, AccessPending)
	mustUpsertAccess(t, store, 400, AccessDenied)
	controller.setLogs("ready")
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	service.logs(context.Background(), nil, privateMessage(200, "/logs", 2, 0))
	service.logs(context.Background(), nil, privateMessage(300, "/logs", 3, 0))
	service.logs(context.Background(), nil, privateMessage(400, "/logs", 4, 0))
	service.logs(context.Background(), nil, privateMessage(500, "/logs", 5, 0))
	service.logs(context.Background(), nil, messageUpdate(200, -200, models.ChatTypeGroup, "/logs", 6, 0))

	drafts := waitForDraftCount(t, client, 2)
	factory.wait(t)
	factory.wait(t)
	recipients := map[int64]int{}
	for _, draft := range drafts {
		recipients[draft.chatID]++
	}
	if len(drafts) != 2 || recipients[testOwnerID] != 1 || recipients[200] != 1 {
		t.Fatalf("draft recipients = %#v, want owner and approved private user", drafts)
	}
	service.logStreams.mu.Lock()
	streamCount := len(service.logStreams.streams)
	service.logStreams.mu.Unlock()
	if streamCount != 2 {
		t.Fatalf("active streams = %d, want 2", streamCount)
	}
	stopLogService(t, service)
}

func TestLogStreamIsIdempotentAndKeepsStableNonzeroDraftID(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	controller.setLogs("first")
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	ticker := factory.wait(t)
	first := waitForDraftCount(t, client, 1)[0]
	if first.draftID == "" || first.draftID == "0" {
		t.Fatalf("initial draft ID = %q, want stable nonzero ID", first.draftID)
	}
	if _, err := strconv.ParseUint(first.draftID, 10, 64); err != nil {
		t.Fatalf("initial draft ID %q is not numeric: %v", first.draftID, err)
	}

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs start", 2, 0))
	waitForLogCondition(t, "already-running response", func() bool { return len(client.snapshotSends()) >= 2 })
	alreadyRunning := false
	for _, send := range client.snapshotSends() {
		alreadyRunning = alreadyRunning || strings.Contains(send.text, "already running")
	}
	if !alreadyRunning {
		t.Fatal("repeated start did not report the existing stream")
	}
	service.logStreams.mu.Lock()
	streamCount := len(service.logStreams.streams)
	service.logStreams.mu.Unlock()
	if streamCount != 1 {
		t.Fatalf("active streams after repeated start = %d, want 1", streamCount)
	}

	controller.setLogs("second")
	ticker.ch <- time.Now()
	drafts := waitForDraftCount(t, client, 2)
	if drafts[1].draftID != first.draftID {
		t.Fatalf("draft ID changed from %q to %q", first.draftID, drafts[1].draftID)
	}
	stopLogService(t, service)
}

func TestLogDraftRefreshesAtMostOncePerTickAndHeartbeatsAfterTwentySeconds(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	clock := &fakeLogClock{now: time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)}
	service.now = clock.Now
	controller.setLogs("first")
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	ticker := factory.wait(t)
	waitForDraftCount(t, client, 1)

	controller.setLogs("changed")
	ticker.ch <- clock.Now()
	waitForDraftCount(t, client, 2)
	if got := len(client.snapshotDrafts()); got != 2 {
		t.Fatalf("draft count after one changed tick = %d, want 2 total", got)
	}

	clock.Advance(19 * time.Second)
	ticker.ch <- clock.Now()
	waitForLogCalls(t, controller, 3)
	if got := len(client.snapshotDrafts()); got != 2 {
		t.Fatalf("draft count before heartbeat = %d, want 2", got)
	}

	clock.Advance(time.Second)
	ticker.ch <- clock.Now()
	waitForDraftCount(t, client, 3)
	if got := len(client.snapshotDrafts()); got != 3 {
		t.Fatalf("draft count at heartbeat = %d, want 3", got)
	}
	stopLogService(t, service)
}

func TestLogDraftFailureFallsBackOnceAndEditsSameMessageOnlyOnChange(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	controller.setLogs("first")
	client.setDraftError(errors.New("draft unsupported"))
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	ticker := factory.wait(t)
	waitForDraftCount(t, client, 1)
	sends := waitForSendCount(t, client, 1)
	outputID := sends[0].messageID
	if sends[0].text != formatLogs([]string{"first"}, false) {
		t.Fatalf("fallback text = %q, want current logs", sends[0].text)
	}

	controller.setLogs("second")
	ticker.ch <- time.Now()
	edits := waitForEditCount(t, client, 1)
	if edits[0].messageID != outputID {
		t.Fatalf("edit message ID = %d, want fallback ID %d", edits[0].messageID, outputID)
	}
	if got := len(client.snapshotDrafts()); got != 1 {
		t.Fatalf("draft attempts after fallback = %d, want 1", got)
	}

	ticker.ch <- time.Now()
	waitForLogCalls(t, controller, 3)
	if got := len(client.snapshotEdits()); got != 1 {
		t.Fatalf("edits for unchanged persistent content = %d, want 1", got)
	}
	if got := len(client.snapshotSends()); got != 1 {
		t.Fatalf("fallback sends = %d, want exactly 1", got)
	}

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs stop", 2, 0))
	edits = waitForEditCount(t, client, 2)
	final := edits[1]
	if final.messageID != outputID || final.text != formatLogs([]string{"second"}, true) {
		t.Fatalf("final edit = %#v, want stopped logs on message %d", final, outputID)
	}
	markup, ok := final.replyMarkup.(*models.InlineKeyboardMarkup)
	if !ok || len(markup.InlineKeyboard) != 0 {
		t.Fatalf("final reply markup = %#v, want empty inline keyboard", final.replyMarkup)
	}
	stopLogService(t, service)
}

func TestLogRevokeAndShutdownDeleteOutputWithoutPublishingFinalText(t *testing.T) {
	t.Run("revoke", func(t *testing.T) {
		service, _, controller, client := newServiceHarness(t)
		controller.setLogs("secret")
		client.setDraftError(errors.New("draft unsupported"))
		factory := newFakeLogTickerFactory(nil)
		service.logStreams.newTicker = factory.New
		service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
		factory.wait(t)
		outputID := waitForSendCount(t, client, 1)[0].messageID
		beforeSends, beforeEdits := len(client.snapshotSends()), len(client.snapshotEdits())

		service.authorizationMu.Lock()
		service.logStreams.revokeLocked(context.Background(), testOwnerID)
		service.authorizationMu.Unlock()
		waitForLogCondition(t, "revoked output deletion", func() bool { return len(client.snapshotDeletes()) == 1 })
		deletes := client.snapshotDeletes()
		if len(deletes[0].messageIDs) != 1 || deletes[0].messageIDs[0] != outputID {
			t.Fatalf("revoke deleted %#v, want output message %d", deletes[0].messageIDs, outputID)
		}
		if len(client.snapshotSends()) != beforeSends || len(client.snapshotEdits()) != beforeEdits {
			t.Fatal("revoke published final log text")
		}
		stopLogService(t, service)
	})

	t.Run("shutdown", func(t *testing.T) {
		service, _, controller, client := newServiceHarness(t)
		controller.setLogs("secret")
		client.setDraftError(errors.New("draft unsupported"))
		factory := newFakeLogTickerFactory(nil)
		service.logStreams.newTicker = factory.New
		service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
		factory.wait(t)
		outputID := waitForSendCount(t, client, 1)[0].messageID
		beforeSends, beforeEdits := len(client.snapshotSends()), len(client.snapshotEdits())

		stopLogService(t, service)
		deletes := client.snapshotDeletes()
		if len(deletes) != 1 || len(deletes[0].messageIDs) != 1 || deletes[0].messageIDs[0] != outputID {
			t.Fatalf("shutdown deleted %#v, want output message %d", deletes, outputID)
		}
		if len(client.snapshotSends()) != beforeSends || len(client.snapshotEdits()) != beforeEdits {
			t.Fatal("shutdown published final log text")
		}
	})
}

func TestLogFlushHonorsDeadlineWhileRefreshIsBlocked(t *testing.T) {
	service, _, controller, _ := newServiceHarness(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	controller.logsHook = func() {
		once.Do(func() { close(entered) })
		<-release
	}
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New
	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("refresh did not enter blocked controller snapshot")
	}

	flushDone := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	go func() { flushDone <- service.Flush(ctx) }()

	var result error
	returnedBeforeRelease := false
	select {
	case result = <-flushDone:
		returnedBeforeRelease = true
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if !returnedBeforeRelease {
		select {
		case result = <-flushDone:
		case <-time.After(time.Second):
			t.Fatal("Flush remained blocked after controller refresh was released")
		}
	}
	if !returnedBeforeRelease {
		t.Fatalf("Flush ignored its deadline while refresh was blocked; returned %v only after release", result)
	}
	if !errors.Is(result, context.DeadlineExceeded) {
		t.Fatalf("Flush result = %v, want context deadline exceeded", result)
	}
}

func TestLogStopRestartDoesNotLetOldStreamDeleteNewPointer(t *testing.T) {
	service, _, controller, _ := newServiceHarness(t)
	controller.setLogs("first")
	stopRelease := make(chan struct{})
	factory := newFakeLogTickerFactory(stopRelease)
	service.logStreams.newTicker = factory.New

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	oldTicker := factory.wait(t)
	waitForLogCalls(t, controller, 1)
	service.logStreams.mu.Lock()
	oldStream := service.logStreams.streams[testOwnerID]
	service.logStreams.mu.Unlock()

	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs stop", 2, 0))
	select {
	case <-oldTicker.stopEntered:
	case <-time.After(time.Second):
		close(stopRelease)
		t.Fatal("old stream did not begin stopping")
	}
	controller.setLogs("second")
	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 3, 0))
	factory.wait(t)
	service.logStreams.mu.Lock()
	newStream := service.logStreams.streams[testOwnerID]
	service.logStreams.mu.Unlock()
	if newStream == nil || newStream == oldStream {
		close(stopRelease)
		t.Fatalf("restart stream pointer = %p, old pointer = %p", newStream, oldStream)
	}

	close(stopRelease)
	waitForLogCondition(t, "old stream completion", func() bool {
		service.logStreams.mu.Lock()
		defer service.logStreams.mu.Unlock()
		return service.logStreams.streams[testOwnerID] == newStream
	})
	stopLogService(t, service)
}

func TestLogDeliveryPayloadsStayWithinTelegramLimit(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	controller.setLogs(strings.Repeat("😀<&>", telegramTextLimit))
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New
	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
	factory.wait(t)
	waitForDraftCount(t, client, 1)
	service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs stop", 2, 0))
	waitForSendCount(t, client, 2)

	assertBounded := func(kind, text string) {
		t.Helper()
		visible := strings.NewReplacer("<b>", "", "</b>", "", "<i>", "", "</i>", "", "<pre>", "", "</pre>", "").Replace(text)
		visible = html.UnescapeString(visible)
		if units := utf16Units(visible); units > telegramTextLimit {
			t.Fatalf("%s payload has %d UTF-16 units, limit %d", kind, units, telegramTextLimit)
		}
	}
	for _, draft := range client.snapshotDrafts() {
		assertBounded("draft", draft.text)
	}
	for _, send := range client.snapshotSends() {
		assertBounded("send", send.text)
	}
	for _, edit := range client.snapshotEdits() {
		assertBounded("edit", edit.text)
	}
	stopLogService(t, service)
}

func requireLogStopMarkup(t *testing.T, markup models.ReplyMarkup) {
	t.Helper()
	keyboard, ok := markup.(*models.InlineKeyboardMarkup)
	if !ok || len(keyboard.InlineKeyboard) != 1 || len(keyboard.InlineKeyboard[0]) != 1 {
		t.Fatalf("reply markup = %#v, want one-button Stop keyboard", markup)
	}
	button := keyboard.InlineKeyboard[0][0]
	if button.Text != "Stop" || button.CallbackData != "logs:stop" {
		t.Fatalf("reply button = %#v, want logs:stop Stop button", button)
	}
}

func requireOlderLogsButton(t *testing.T, markup models.ReplyMarkup, want bool) {
	t.Helper()
	keyboard, ok := markup.(*models.InlineKeyboardMarkup)
	if !ok {
		t.Fatalf("reply markup = %#v, want inline keyboard", markup)
	}
	found := false
	for _, row := range keyboard.InlineKeyboard {
		for _, button := range row {
			if button.Text == "Older logs" && button.CallbackData == "logs:older" {
				found = true
			}
		}
	}
	if found != want {
		t.Fatalf("Older logs button present = %v, want %v: %#v", found, want, keyboard.InlineKeyboard)
	}
}

func requireNoLogKeyboard(t *testing.T, markup models.ReplyMarkup) {
	t.Helper()
	if markup == nil {
		return
	}
	keyboard, ok := markup.(*models.InlineKeyboardMarkup)
	if !ok || len(keyboard.InlineKeyboard) != 0 {
		t.Fatalf("final reply markup = %#v, want no keyboard", markup)
	}
}

func TestLogLateDraftFailureDeletesControlAndPreservesPayloadMetadata(t *testing.T) {
	t.Run("late fallback and edit finalization", func(t *testing.T) {
		service, _, controller, client := newServiceHarness(t)
		controller.setLogs("first")
		factory := newFakeLogTickerFactory(nil)
		service.logStreams.newTicker = factory.New
		service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
		ticker := factory.wait(t)
		drafts := waitForDraftCount(t, client, 1)
		control := waitForSendCount(t, client, 1)[0]
		if drafts[0].parseMode != models.ParseModeHTML {
			t.Fatalf("initial draft parse mode = %q, want HTML", drafts[0].parseMode)
		}
		if control.parseMode != models.ParseModeHTML {
			t.Fatalf("control parse mode = %q, want HTML", control.parseMode)
		}
		requireLogStopMarkup(t, control.replyMarkup)

		client.setDraftError(errors.New("draft became unavailable"))
		controller.setLogs("second")
		ticker.ch <- time.Now()
		drafts = waitForDraftCount(t, client, 2)
		sends := waitForSendCount(t, client, 2)
		waitForLogCondition(t, "redundant control deletion", func() bool { return len(client.snapshotDeletes()) >= 1 })
		fallback := sends[1]
		if drafts[1].parseMode != models.ParseModeHTML {
			t.Fatalf("failed draft parse mode = %q, want HTML", drafts[1].parseMode)
		}
		if fallback.parseMode != models.ParseModeHTML {
			t.Fatalf("fallback parse mode = %q, want HTML", fallback.parseMode)
		}
		requireLogStopMarkup(t, fallback.replyMarkup)
		deletes := client.snapshotDeletes()
		if len(deletes[0].messageIDs) != 1 || deletes[0].messageIDs[0] != control.messageID {
			t.Fatalf("late fallback deleted %#v, want redundant control %d", deletes[0].messageIDs, control.messageID)
		}
		operations := client.snapshotOperations()
		var fallbackSendIndex, controlDeleteIndex = -1, -1
		for i, operation := range operations {
			if operation.method == "send" && operation.messageID == fallback.messageID {
				fallbackSendIndex = i
			}
			if operation.method == "delete" && len(operation.messageIDs) == 1 && operation.messageIDs[0] == control.messageID {
				controlDeleteIndex = i
			}
		}
		if fallbackSendIndex < 0 || controlDeleteIndex <= fallbackSendIndex {
			t.Fatalf("fallback/control operation order = %#v, want fallback send before control delete", operations)
		}

		controller.setLogs("third")
		ticker.ch <- time.Now()
		edits := waitForEditCount(t, client, 1)
		if edits[0].messageID != fallback.messageID || edits[0].parseMode != models.ParseModeHTML {
			t.Fatalf("active edit = %#v, want HTML edit of fallback %d", edits[0], fallback.messageID)
		}
		requireLogStopMarkup(t, edits[0].replyMarkup)

		service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs stop", 2, 0))
		edits = waitForEditCount(t, client, 2)
		final := edits[1]
		if final.messageID != fallback.messageID || final.parseMode != models.ParseModeHTML {
			t.Fatalf("final edit = %#v, want HTML edit of fallback %d", final, fallback.messageID)
		}
		requireNoLogKeyboard(t, final.replyMarkup)
		stopLogService(t, service)
	})

	t.Run("draft finalization", func(t *testing.T) {
		service, _, controller, client := newServiceHarness(t)
		controller.setLogs("draft mode")
		factory := newFakeLogTickerFactory(nil)
		service.logStreams.newTicker = factory.New
		service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs", 1, 0))
		factory.wait(t)
		draft := waitForDraftCount(t, client, 1)[0]
		control := waitForSendCount(t, client, 1)[0]
		if draft.parseMode != models.ParseModeHTML || control.parseMode != models.ParseModeHTML {
			t.Fatalf("draft/control parse modes = %q/%q, want HTML/HTML", draft.parseMode, control.parseMode)
		}
		requireLogStopMarkup(t, control.replyMarkup)

		service.logs(context.Background(), nil, privateMessage(testOwnerID, "/logs stop", 2, 0))
		sends := waitForSendCount(t, client, 2)
		final := sends[1]
		if final.parseMode != models.ParseModeHTML {
			t.Fatalf("draft-mode final parse mode = %q, want HTML", final.parseMode)
		}
		requireNoLogKeyboard(t, final.replyMarkup)
		stopLogService(t, service)
	})
}

func TestLogBlockedRefreshAllowsPersistedRevokeAndRejectsStaleUpdates(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	controller.setLogs("first")
	factory := newFakeLogTickerFactory(nil)
	service.logStreams.newTicker = factory.New
	service.logs(context.Background(), nil, privateMessage(200, "/logs", 1, 0))
	ticker := factory.wait(t)
	waitForDraftCount(t, client, 1)
	waitForSendCount(t, client, 1)
	service.logStreams.mu.Lock()
	stream := service.logStreams.streams[200]
	service.logStreams.mu.Unlock()

	entered := make(chan struct{})
	release := make(chan struct{})
	var blockOnce sync.Once
	client.setDraftHook(func(recordedDraft) {
		blockOnce.Do(func() {
			close(entered)
			<-release
		})
	})
	controller.setLogs("blocked update")
	ticker.ch <- time.Now()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("outbound refresh did not block")
	}

	revokeDone := make(chan struct{})
	go func() {
		service.accessCallback(context.Background(), nil, privateCallback(testOwnerID, "access:revoke:200", "revoke"))
		close(revokeDone)
	}()
	waitForAnswer(t, client, "revoke")
	waitForLogCondition(t, "revoke persistence while outbound edit is blocked", func() bool {
		_, ok := store.Get(200)
		return !ok
	})

	close(release)
	select {
	case <-revokeDone:
	case <-time.After(time.Second):
		t.Fatal("revoke did not complete after outbound refresh")
	}
	if _, ok := store.Get(200); ok {
		t.Fatal("approved access remains persisted after revoke")
	}
	beforeDrafts := len(client.snapshotDrafts())
	beforeSends := len(client.snapshotSends())
	beforeEdits := len(client.snapshotEdits())
	beforeDeletes := len(client.snapshotDeletes())
	service.logStreams.refresh(stream)
	service.logs(context.Background(), nil, privateMessage(200, "/logs stop", 2, 0))
	if len(client.snapshotDrafts()) != beforeDrafts ||
		len(client.snapshotSends()) != beforeSends ||
		len(client.snapshotEdits()) != beforeEdits ||
		len(client.snapshotDeletes()) != beforeDeletes {
		t.Fatalf("post-revoke refresh or stale stop changed delivery: operations=%#v", client.snapshotOperations())
	}
	stopLogService(t, service)
}

func TestLogPollingContextCancellationCleansPersistentUIWithoutFinalText(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		name := "draft"
		if fallback {
			name = "fallback"
		}
		t.Run(name, func(t *testing.T) {
			service, _, controller, client := newServiceHarness(t)
			controller.setLogs("persistent")
			if fallback {
				client.setDraftError(errors.New("draft unavailable"))
			}
			factory := newFakeLogTickerFactory(nil)
			service.logStreams.newTicker = factory.New
			ctx, cancel := context.WithCancel(context.Background())
			startDone := make(chan struct{})
			go func() {
				service.Start(ctx)
				close(startDone)
			}()
			select {
			case <-client.started:
			case <-time.After(time.Second):
				cancel()
				t.Fatal("Telegram polling did not start")
			}

			service.logs(ctx, nil, privateMessage(testOwnerID, "/logs", 1, 0))
			factory.wait(t)
			waitForDraftCount(t, client, 1)
			persistent := waitForSendCount(t, client, 1)[0]
			beforeSends, beforeEdits := len(client.snapshotSends()), len(client.snapshotEdits())
			cancel()
			select {
			case <-startDone:
			case <-time.After(time.Second):
				t.Fatal("Service.Start did not return after polling cancellation")
			}
			waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
			defer waitCancel()
			if err := service.logStreams.wait(waitCtx); err != nil {
				t.Fatalf("wait for canceled polling stream: %v", err)
			}
			waitForLogCondition(t, "polling cancellation UI deletion", func() bool {
				return len(client.snapshotDeletes()) >= 1
			})
			deletes := client.snapshotDeletes()
			if len(deletes) != 1 || len(deletes[0].messageIDs) != 1 || deletes[0].messageIDs[0] != persistent.messageID {
				t.Fatalf("polling cancellation deleted %#v, want persistent UI %d", deletes, persistent.messageID)
			}
			if len(client.snapshotSends()) != beforeSends || len(client.snapshotEdits()) != beforeEdits {
				t.Fatal("polling cancellation published final log text")
			}
		})
	}
}
