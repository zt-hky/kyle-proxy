package telegram

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-telegram/bot/models"
	"globalprotect-manager/internal/vpn"
)

func TestEventStreamResetsIdleDeadlineAndStartsNewBurst(t *testing.T) {
	service, _, controller, client := newServiceHarness(t)
	service.eventStreams.idleTimeout = 150 * time.Millisecond
	dispatchCtx, cancelDispatch := context.WithCancel(context.Background())
	defer cancelDispatch()
	go service.dispatchEvents(dispatchCtx)

	first := vpn.Event{Kind: vpn.EventKindState, Name: "connecting", Detail: "first"}
	second := vpn.Event{Kind: vpn.EventKindPhase, Name: "auth", Detail: "second"}
	controller.emit(first)
	firstSend := waitForSendCount(t, client, 1)[0]
	if firstSend.text != formatEvents([]vpn.Event{first}, false) || firstSend.parseMode != models.ParseModeHTML {
		t.Fatalf("first event send = %#v", firstSend)
	}

	time.Sleep(100 * time.Millisecond)
	controller.emit(second)
	activeEdit := waitForEditCount(t, client, 1)[0]
	if activeEdit.messageID != firstSend.messageID || activeEdit.text != formatEvents([]vpn.Event{first, second}, false) || activeEdit.parseMode != models.ParseModeHTML {
		t.Fatalf("active stream edit = %#v", activeEdit)
	}

	time.Sleep(80 * time.Millisecond)
	if edits := client.snapshotEdits(); len(edits) != 1 {
		t.Fatalf("idle deadline was not reset; edits=%#v", edits)
	}
	idleEdit := waitForEditCount(t, client, 2)[1]
	if idleEdit.messageID != firstSend.messageID || idleEdit.text != formatEvents([]vpn.Event{first, second}, true) || !strings.Contains(idleEdit.text, "idle") {
		t.Fatalf("idle final edit = %#v", idleEdit)
	}

	third := vpn.Event{Kind: vpn.EventKindAction, Name: "reconnect", Detail: "new burst"}
	controller.emit(third)
	sends := waitForSendCount(t, client, 2)
	if sends[1].messageID == firstSend.messageID || sends[1].text != formatEvents([]vpn.Event{third}, false) {
		t.Fatalf("post-idle send = %#v, prior message=%d", sends[1], firstSend.messageID)
	}

	flushCtx, cancelFlush := context.WithTimeout(context.Background(), time.Second)
	defer cancelFlush()
	if err := service.Flush(flushCtx); err != nil {
		t.Fatalf("flush event streams: %v", err)
	}
	finalEdit := waitForEditCount(t, client, 3)[2]
	if finalEdit.messageID != sends[1].messageID || finalEdit.text != formatEvents([]vpn.Event{third}, true) {
		t.Fatalf("shutdown final edit = %#v", finalEdit)
	}
	time.Sleep(180 * time.Millisecond)
	if edits := client.snapshotEdits(); len(edits) != 3 {
		t.Fatalf("shutdown left an idle timer active; edits=%#v", edits)
	}
}
