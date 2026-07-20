package telegram

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"globalprotect-manager/internal/vpn"
)

type fifoTestTicker struct {
	ticks chan time.Time
}

func (t *fifoTestTicker) C() <-chan time.Time { return t.ticks }
func (t *fifoTestTicker) Stop()               {}

func waitForOperationCount(t *testing.T, client *fakeTelegramClient, method string, want int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		count := 0
		for _, operation := range client.snapshotOperations() {
			if operation.method == method {
				count++
			}
		}
		if count >= want {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("%s operation count = %d, want at least %d; operations=%#v", method, count, want, client.snapshotOperations())
		case <-ticker.C:
		}
	}
}

func requireEventQueueAccounting(t *testing.T, service *Service, length, head int, inFlight bool) {
	t.Helper()
	service.eventMu.Lock()
	defer service.eventMu.Unlock()
	if len(service.events) != length || service.eventHead != head || service.eventInFlight != inFlight {
		t.Fatalf("event accounting = len:%d head:%d in-flight:%v, want len:%d head:%d in-flight:%v", len(service.events), service.eventHead, service.eventInFlight, length, head, inFlight)
	}
}

func waitForEventDelivery(t *testing.T, client *fakeTelegramClient, texts map[string]struct{}, want int) []recordedSend {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		var delivered []recordedSend
		for _, send := range client.snapshotSends() {
			if _, ok := texts[send.text]; ok {
				delivered = append(delivered, send)
			}
		}
		if len(delivered) >= want {
			return delivered
		}
		select {
		case <-deadline.C:
			t.Fatalf("event delivery count = %d, want %d; sends=%#v", len(delivered), want, client.snapshotSends())
		case <-ticker.C:
		}
	}
}

func waitForEventQueueIdle(t *testing.T, service *Service, length, head int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		service.eventMu.Lock()
		gotLength := len(service.events)
		gotHead := service.eventHead
		inFlight := service.eventInFlight
		service.eventMu.Unlock()
		if gotLength == length && gotHead == head && !inFlight {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("event queue did not become idle: len=%d head=%d in-flight=%v", gotLength, gotHead, inFlight)
		case <-ticker.C:
		}
	}
}

func TestActiveLogDraftAndEditTrafficDoesNotEnterEventFIFOAccounting(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	controller.setLogs("draft-one")

	manualTicker := &fifoTestTicker{ticks: make(chan time.Time, 4)}
	tickerReady := make(chan struct{})
	service.logStreams.newTicker = func(time.Duration) logTicker {
		close(tickerReady)
		return manualTicker
	}
	service.logs(context.Background(), nil, privateMessage(200, "/logs", 1, 0))
	select {
	case <-tickerReady:
	case <-time.After(time.Second):
		t.Fatal("live log stream did not start")
	}
	waitForOperationCount(t, client, "draft", 1)
	waitForOperationCount(t, client, "send", 1)
	requireEventQueueAccounting(t, service, 0, 0, false)

	dispatchCtx, cancelDispatch := context.WithCancel(context.Background())
	defer cancelDispatch()
	go service.dispatchEvents(dispatchCtx)
	firstEntered := make(chan struct{})
	firstRelease := make(chan struct{})
	var firstOnce sync.Once
	client.setSendHook(func(send recordedSend) {
		if send.chatID == testOwnerID && strings.Contains(send.text, "event-one") {
			firstOnce.Do(func() { close(firstEntered) })
			<-firstRelease
		}
	})

	events := []vpn.Event{
		{ID: 1, Kind: vpn.EventKindAction, Name: "event-one", Detail: "first", Status: vpn.Status{State: vpn.StateConnected}},
		{ID: 2, Kind: vpn.EventKindAction, Name: "event-two", Detail: "second", Status: vpn.Status{State: vpn.StateConnected}},
		{ID: 3, Kind: vpn.EventKindAction, Name: "event-three", Detail: "third", Status: vpn.Status{State: vpn.StateConnected}},
	}
	controller.emit(events[0])
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first event delivery did not enter the bot client")
	}
	requireEventQueueAccounting(t, service, 1, 1, true)

	client.setDraftError(errors.New("force edit-mode fallback"))
	controller.setLogs("fallback-two")
	manualTicker.ticks <- time.Now()
	waitForOperationCount(t, client, "draft", 2)
	waitForOperationCount(t, client, "delete", 1)
	requireEventQueueAccounting(t, service, 1, 1, true)

	client.setDraftError(nil)
	controller.setLogs("edit-three")
	manualTicker.ticks <- time.Now()
	waitForOperationCount(t, client, "edit", 1)
	requireEventQueueAccounting(t, service, 1, 1, true)

	controller.emit(events[1])
	controller.emit(events[2])
	requireEventQueueAccounting(t, service, 3, 1, true)
	close(firstRelease)

	waitForLogCondition(t, "aggregated event delivery", func() bool {
		eventSends, eventEdits := 0, 0
		for _, send := range client.snapshotSends() {
			if strings.Contains(send.text, "GlobalProtect events") {
				eventSends++
			}
		}
		for _, edit := range client.snapshotEdits() {
			if strings.Contains(edit.text, "GlobalProtect events") {
				eventEdits++
			}
		}
		return eventSends == 2 && eventEdits == 4
	})
	for _, chatID := range []int64{testOwnerID, 200} {
		var initial *recordedSend
		for _, send := range client.snapshotSends() {
			if send.chatID == chatID && strings.Contains(send.text, "GlobalProtect events") {
				copy := send
				initial = &copy
				break
			}
		}
		var edits []recordedEdit
		for _, edit := range client.snapshotEdits() {
			if edit.chatID == chatID && strings.Contains(edit.text, "GlobalProtect events") {
				edits = append(edits, edit)
			}
		}
		if initial == nil || len(edits) != 2 {
			t.Fatalf("recipient %d aggregation = initial:%#v edits:%#v", chatID, initial, edits)
		}
		final := edits[len(edits)-1]
		if final.messageID != initial.messageID || final.text != formatEvents(events, false) {
			t.Fatalf("recipient %d final aggregation = %#v, initial message %d", chatID, final, initial.messageID)
		}
	}
	waitForEventQueueIdle(t, service, len(events), len(events))

	flushCtx, cancelFlush := context.WithTimeout(context.Background(), time.Second)
	defer cancelFlush()
	if err := service.Flush(flushCtx); err != nil {
		t.Fatalf("flush concurrent log and event traffic: %v", err)
	}
}
