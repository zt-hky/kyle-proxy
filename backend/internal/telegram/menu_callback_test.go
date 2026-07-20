package telegram

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/go-telegram/bot/models"
	"globalprotect-manager/internal/vpn"
)

func menuCallbackUpdate(userID int64, data, callbackID string, messageID int) *models.Update {
	update := privateCallback(userID, data, callbackID)
	update.CallbackQuery.Message.Message.ID = messageID
	return update
}

func requireOperationPrefix(t *testing.T, operations []recordedOperation, methods ...string) {
	t.Helper()
	if len(operations) < len(methods) {
		t.Fatalf("operations = %#v, want prefix %v", operations, methods)
	}
	for i, method := range methods {
		if operations[i].method != method {
			t.Fatalf("operation %d = %q, want %q; all operations = %#v", i, operations[i].method, method, operations)
		}
	}
}

func requireSingleOriginDeletion(t *testing.T, client *fakeTelegramClient, chatID int64, messageID int) {
	t.Helper()
	deletes := client.snapshotDeletes()
	if len(deletes) != 1 || deletes[0].chatID != chatID || len(deletes[0].messageIDs) != 1 || deletes[0].messageIDs[0] != messageID {
		t.Fatalf("deletions = %#v, want one deletion of chat=%d message=%d", deletes, chatID, messageID)
	}
}

func TestMenuCallbacksAcknowledgeThenDeleteOriginBeforeSynchronousResult(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		setup  func(*fakeVPNController)
		assert func(*testing.T, *Service, *fakeVPNController)
	}{
		{
			name: "status",
			data: "vpn:status",
		},
		{
			name: "main menu",
			data: "menu:main",
		},
		{
			name: "connect",
			data: "vpn:connect",
			setup: func(controller *fakeVPNController) {
				controller.setSavedOTP(true)
			},
			assert: func(t *testing.T, _ *Service, controller *fakeVPNController) {
				t.Helper()
				connect, _, _ := controller.counts()
				if connect != 1 {
					t.Fatalf("connect count = %d, want 1", connect)
				}
			},
		},
		{
			name: "disconnect",
			data: "vpn:disconnect",
			assert: func(t *testing.T, _ *Service, controller *fakeVPNController) {
				t.Helper()
				_, _, disconnect := controller.counts()
				if disconnect != 1 {
					t.Fatalf("disconnect count = %d, want 1", disconnect)
				}
			},
		},
		{
			name: "OTP prompt",
			data: "vpn:otp",
			setup: func(controller *fakeVPNController) {
				controller.setStatus(vpn.Status{State: vpn.StateConnecting, AwaitingOTP: true})
			},
			assert: func(t *testing.T, service *Service, _ *fakeVPNController) {
				t.Helper()
				service.mu.Lock()
				prompt, ok := service.pending[200]
				service.mu.Unlock()
				if !ok || prompt.Kind != "followup" {
					t.Fatalf("pending OTP = %#v, %v; want followup", prompt, ok)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service, store, controller, client := newServiceHarness(t)
			service.logStreams.useDrafts = false
			mustUpsertAccess(t, store, 200, AccessApproved)
			if tc.setup != nil {
				tc.setup(controller)
			}

			const originID = 701
			service.callback(context.Background(), nil, menuCallbackUpdate(200, tc.data, "callback", originID))
			waitForSendCount(t, client, 1)

			operations := client.snapshotOperations()
			requireOperationPrefix(t, operations, "answer", "delete", "send")
			requireSingleOriginDeletion(t, client, 200, originID)
			if tc.assert != nil {
				tc.assert(t, service, controller)
			}
		})
	}
}

func TestMenuConnectDeletesOriginBeforeControllerAction(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	mustUpsertAccess(t, store, 200, AccessApproved)
	controller.setSavedOTP(true)
	controller.setConnectHook(func() {
		requireOperationPrefix(t, client.snapshotOperations(), "answer", "delete")
	})

	service.callback(context.Background(), nil, menuCallbackUpdate(200, "vpn:connect", "connect", 702))
	waitForSendCount(t, client, 1)

	connect, _, _ := controller.counts()
	if connect != 1 {
		t.Fatalf("connect count = %d, want 1", connect)
	}
	requireOperationPrefix(t, client.snapshotOperations(), "answer", "delete", "send")
}

type disconnectOrderController struct {
	*fakeVPNController
	beforeDisconnect func()
}

func (c *disconnectOrderController) Disconnect() error {
	c.beforeDisconnect()
	return c.fakeVPNController.Disconnect()
}

func TestMenuDisconnectDeletesOriginBeforeControllerAction(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	service.controller = &disconnectOrderController{
		fakeVPNController: controller,
		beforeDisconnect: func() {
			requireOperationPrefix(t, client.snapshotOperations(), "answer", "delete")
		},
	}

	service.callback(context.Background(), nil, menuCallbackUpdate(200, "vpn:disconnect", "disconnect", 702))

	_, _, disconnect := controller.counts()
	if disconnect != 1 {
		t.Fatalf("disconnect count = %d, want 1", disconnect)
	}
	requireOperationPrefix(t, client.snapshotOperations(), "answer", "delete", "send")
}

func TestMenuLogsDeletesOriginBeforeStartingStream(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	controller.setLogs("line")
	observed := make(chan []recordedOperation, 1)
	controller.logsHook = func() {
		select {
		case observed <- client.snapshotOperations():
		default:
		}
	}

	service.callback(context.Background(), nil, menuCallbackUpdate(200, "menu:logs", "logs", 703))
	select {
	case operations := <-observed:
		requireOperationPrefix(t, operations, "answer", "delete")
	case <-time.After(time.Second):
		t.Fatal("live logs action did not reach the controller")
	}
	requireSingleOriginDeletion(t, client, 200, 703)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := service.Flush(ctx); err != nil {
		t.Fatalf("stop live logs: %v", err)
	}
}

func TestMenuDeletionFailureDoesNotBlockActionOrLeakAdapterError(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	service.logStreams.useDrafts = false
	mustUpsertAccess(t, store, 200, AccessApproved)
	controller.setSavedOTP(true)
	secret := "delete-adapter-secret"
	client.setDeleteError(errors.New(secret))

	var diagnostics bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&diagnostics)
	defer log.SetOutput(oldWriter)

	service.callback(context.Background(), nil, menuCallbackUpdate(200, "vpn:connect", "connect", 704))
	waitForSendCount(t, client, 1)

	connect, _, _ := controller.counts()
	if connect != 1 {
		t.Fatalf("connect count after deletion failure = %d, want 1", connect)
	}
	requireOperationPrefix(t, client.snapshotOperations(), "answer", "delete", "send")
	if strings.Contains(diagnostics.String(), secret) {
		t.Fatalf("deletion diagnostic leaked adapter error: %q", diagnostics.String())
	}
	if !strings.Contains(diagnostics.String(), "menu origin deletion failed messages=[704]") || !strings.Contains(diagnostics.String(), "error=") {
		t.Fatalf("deletion diagnostic = %q, want safe label, message ID, and error type", diagnostics.String())
	}
}

func TestIgnoredMenuCallbacksOnlyAcknowledge(t *testing.T) {
	tests := []struct {
		name     string
		userID   int64
		data     string
		stopping bool
	}{
		{name: "unknown", userID: 200, data: "vpn:unknown"},
		{name: "malformed", userID: 200, data: "vpn:connect:extra"},
		{name: "unauthorized", userID: 300, data: "vpn:connect"},
		{name: "stopping", userID: testOwnerID, data: "vpn:connect", stopping: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service, store, controller, client := newServiceHarness(t)
			mustUpsertAccess(t, store, 200, AccessApproved)
			if tc.stopping {
				service.BeginShutdown()
			}

			service.callback(context.Background(), nil, menuCallbackUpdate(tc.userID, tc.data, tc.name, 705))

			operations := client.snapshotOperations()
			if len(operations) != 1 || operations[0].method != "answer" {
				t.Fatalf("operations = %#v, want acknowledgement only", operations)
			}
			if got := len(client.snapshotDeletes()); got != 0 {
				t.Fatalf("ignored callback made %d deletion requests", got)
			}
			if got := len(client.snapshotSends()); got != 0 {
				t.Fatalf("ignored callback made %d sends", got)
			}
			if connect, submit, disconnect := controller.counts(); connect != 0 || submit != 0 || disconnect != 0 {
				t.Fatalf("ignored callback controller counts = %d/%d/%d, want zero", connect, submit, disconnect)
			}
		})
	}
}

func TestNonMenuCallbacksDoNotDeleteTheirOriginCards(t *testing.T) {
	t.Run("access decision card", func(t *testing.T) {
		service, store, _, client := newServiceHarness(t)
		mustUpsertAccess(t, store, 200, AccessPending)

		service.accessCallback(context.Background(), nil, menuCallbackUpdate(testOwnerID, "access:approve:200", "approve", 801))

		if got := len(client.snapshotDeletes()); got != 0 {
			t.Fatalf("access decision deleted %d messages", got)
		}
		record, ok := store.Get(200)
		if !ok || record.Status != AccessApproved {
			t.Fatalf("access record = %#v, %v; want approved", record, ok)
		}
		requireOperationPrefix(t, client.snapshotOperations(), "answer", "send")
	})

	t.Run("logs stop card", func(t *testing.T) {
		service, store, _, client := newServiceHarness(t)
		mustUpsertAccess(t, store, 200, AccessApproved)

		service.logsCallback(context.Background(), nil, menuCallbackUpdate(200, "logs:stop", "stop", 802))

		if got := len(client.snapshotDeletes()); got != 0 {
			t.Fatalf("inactive logs stop deleted %d messages", got)
		}
		operations := client.snapshotOperations()
		if len(operations) != 1 || operations[0].method != "answer" {
			t.Fatalf("operations = %#v, want acknowledgement only", operations)
		}
	})
}

func TestOTPClaimBatchDeletesThenSubmitsOnceWithoutSecretLeakage(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	const promptID = 901
	const replyID = 902
	token := "918273-secret-otp"
	deleteSecret := "delete echoed " + token
	submitSecret := "submit rejected " + token
	service.mu.Lock()
	service.pending[200] = pendingOTP{ChatID: 200, PromptMessageID: promptID, Kind: "followup", ExpiresAt: time.Now().Add(time.Minute)}
	service.mu.Unlock()
	client.setDeleteError(errors.New(deleteSecret))
	controller.submitError = errors.New(submitSecret)
	controller.submitHook = func() {
		operations := client.snapshotOperations()
		if len(operations) != 1 || operations[0].method != "delete" {
			t.Fatalf("operations at OTP submission = %#v, want batch deletion first", operations)
		}
	}

	var diagnostics bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&diagnostics)
	defer log.SetOutput(oldWriter)

	reply := privateMessage(200, token, replyID, promptID)
	service.text(context.Background(), nil, reply)
	service.text(context.Background(), nil, reply)

	deletes := client.snapshotDeletes()
	if len(deletes) != 1 || deletes[0].chatID != 200 || len(deletes[0].messageIDs) != 2 || deletes[0].messageIDs[0] != promptID || deletes[0].messageIDs[1] != replyID {
		t.Fatalf("OTP deletions = %#v, want one ordered prompt+reply batch", deletes)
	}
	_, submit, _ := controller.counts()
	if submit != 1 {
		t.Fatalf("OTP submit count = %d, want 1", submit)
	}
	sends := client.snapshotSends()
	if len(sends) != 1 || sends[0].text != formatOTPError() {
		t.Fatalf("OTP error sends = %#v, want one generic error", sends)
	}
	visible := diagnostics.String() + "\n" + sends[0].text
	for _, secret := range []string{token, deleteSecret, submitSecret} {
		if strings.Contains(visible, secret) {
			t.Fatalf("OTP handling leaked %q in %q", secret, visible)
		}
	}
	if !strings.Contains(diagnostics.String(), fmt.Sprintf("messages=[%d %d]", promptID, replyID)) {
		t.Fatalf("OTP deletion diagnostic omitted safe message IDs: %q", diagnostics.String())
	}
}

func TestMenuKeyboardAlwaysOffersLogsAndUsesHTML(t *testing.T) {
	statuses := []vpn.Status{
		{State: vpn.StateDisconnected},
		{State: vpn.StateError},
		{State: vpn.StateConnecting},
		{State: vpn.StateConnecting, AwaitingOTP: true},
		{State: vpn.StateConnected},
	}
	for _, status := range statuses {
		status := status
		t.Run(string(status.State), func(t *testing.T) {
			service, _, controller, client := newServiceHarness(t)
			controller.setStatus(status)

			service.sendMenu(context.Background(), testOwnerID)

			sends := client.snapshotSends()
			if len(sends) != 1 {
				t.Fatalf("menu sends = %d, want 1", len(sends))
			}
			if sends[0].parseMode != models.ParseModeHTML {
				t.Fatalf("menu parse mode = %q, want HTML", sends[0].parseMode)
			}
			markup, ok := sends[0].replyMarkup.(*models.InlineKeyboardMarkup)
			if !ok {
				t.Fatalf("menu markup = %T, want inline keyboard", sends[0].replyMarkup)
			}
			foundLogs := false
			for _, row := range markup.InlineKeyboard {
				for _, button := range row {
					if button.Text == "Logs" && button.CallbackData == "menu:logs" {
						foundLogs = true
					}
				}
			}
			if !foundLogs {
				t.Fatalf("menu keyboard = %#v, want Logs/menu:logs", markup.InlineKeyboard)
			}
		})
	}
}

func TestUserFacingMenuIntegrationSendsHTML(t *testing.T) {
	service, store, controller, client := newServiceHarness(t)
	mustUpsertAccess(t, store, 200, AccessApproved)
	mustUpsertAccess(t, store, 300, AccessPending)

	service.menu(context.Background(), nil, privateMessage(200, "/menu", 1, 0))
	service.accessCallback(context.Background(), nil, menuCallbackUpdate(testOwnerID, "access:approve:300", "approve", 2))
	controller.setStatus(vpn.Status{State: vpn.StateConnecting, AwaitingOTP: true})
	service.callback(context.Background(), nil, menuCallbackUpdate(200, "vpn:otp", "otp", 3))
	service.mu.Lock()
	prompt := service.pending[200]
	service.mu.Unlock()
	controller.submitError = errors.New("adapter details must stay internal")
	service.text(context.Background(), nil, privateMessage(200, "123456", 4, prompt.PromptMessageID))

	sends := client.snapshotSends()
	if len(sends) < 4 {
		t.Fatalf("integration sends = %#v, want menu, access, prompt, and OTP error", sends)
	}
	for i, send := range sends {
		if send.parseMode != models.ParseModeHTML {
			t.Fatalf("send %d parse mode = %q, want HTML; send=%#v", i, send.parseMode, send)
		}
	}
}

func TestLogCallbacksRejectEveryUnauthorizedIdentityAndAccessState(t *testing.T) {
	tests := []struct {
		name      string
		userID    int64
		chatID    int64
		hasRecord bool
		status    AccessStatus
		stopping  bool
	}{
		{name: "mismatched private chat and user", userID: 200, chatID: 201, hasRecord: true, status: AccessApproved},
		{name: "pending", userID: 200, chatID: 200, hasRecord: true, status: AccessPending},
		{name: "denied", userID: 200, chatID: 200, hasRecord: true, status: AccessDenied},
		{name: "revoked", userID: 200, chatID: 200},
		{name: "stopping", userID: testOwnerID, chatID: testOwnerID, stopping: true},
	}
	handlers := []struct {
		name string
		data string
		call func(*Service, *models.Update)
	}{
		{
			name: "menu logs",
			data: "menu:logs",
			call: func(service *Service, update *models.Update) {
				service.callback(context.Background(), nil, update)
			},
		},
		{
			name: "logs stop",
			data: "logs:stop",
			call: func(service *Service, update *models.Update) {
				service.logsCallback(context.Background(), nil, update)
			},
		},
		{
			name: "logs older",
			data: "logs:older",
			call: func(service *Service, update *models.Update) {
				service.logsCallback(context.Background(), nil, update)
			},
		},
	}

	for _, handler := range handlers {
		for _, tc := range tests {
			t.Run(handler.name+"/"+tc.name, func(t *testing.T) {
				service, store, controller, client := newServiceHarness(t)
				if tc.hasRecord {
					mustUpsertAccess(t, store, tc.userID, tc.status)
				}
				if tc.stopping {
					service.BeginShutdown()
				}

				var sentinel *logStream
				if handler.data == "logs:stop" || handler.data == "logs:older" {
					streamCtx, cancel := context.WithCancel(context.Background())
					t.Cleanup(cancel)
					sentinel = &logStream{
						chatID: tc.chatID, userID: tc.userID, ctx: streamCtx, cancel: cancel,
						visibleLines: logPageLines,
					}
					service.logStreams.mu.Lock()
					service.logStreams.streams[tc.userID] = sentinel
					service.logStreams.mu.Unlock()
				}

				update := callbackUpdate(tc.userID, tc.chatID, models.ChatTypePrivate, handler.data, tc.name)
				update.CallbackQuery.Message.Message.ID = 1001
				handler.call(service, update)

				operations := client.snapshotOperations()
				if len(operations) != 1 || operations[0].method != "answer" {
					t.Fatalf("operations = %#v, want acknowledgement only", operations)
				}
				if len(client.snapshotDeletes()) != 0 || len(client.snapshotSends()) != 0 || len(client.snapshotDrafts()) != 0 || len(client.snapshotEdits()) != 0 {
					t.Fatalf("rejected callback produced Telegram updates: operations=%#v", operations)
				}
				if got := controller.logCallCount(); got != 0 {
					t.Fatalf("rejected callback read logs %d times", got)
				}

				service.logStreams.mu.Lock()
				stream := service.logStreams.streams[tc.userID]
				if sentinel != nil {
					delete(service.logStreams.streams, tc.userID)
				}
				service.logStreams.mu.Unlock()
				if handler.data == "menu:logs" && stream != nil {
					t.Fatal("rejected menu callback started a log stream")
				}
				if sentinel != nil && (stream != sentinel || sentinel.stopped || sentinel.visibleLines != logPageLines) {
					t.Fatalf("rejected log callback mutated stream: got=%p want=%p stopped=%v visible=%d", stream, sentinel, sentinel.stopped, sentinel.visibleLines)
				}
			})
		}
	}
}

func TestRevokedUsersStaleLogCallbacksOnlyAcknowledge(t *testing.T) {
	handlers := []struct {
		name string
		data string
		call func(*Service, *models.Update)
	}{
		{
			name: "menu logs",
			data: "menu:logs",
			call: func(service *Service, update *models.Update) {
				service.callback(context.Background(), nil, update)
			},
		},
		{
			name: "logs stop",
			data: "logs:stop",
			call: func(service *Service, update *models.Update) {
				service.logsCallback(context.Background(), nil, update)
			},
		},
		{
			name: "logs older",
			data: "logs:older",
			call: func(service *Service, update *models.Update) {
				service.logsCallback(context.Background(), nil, update)
			},
		},
	}

	for _, handler := range handlers {
		t.Run(handler.name, func(t *testing.T) {
			service, store, controller, client := newServiceHarness(t)
			mustUpsertAccess(t, store, 200, AccessApproved)
			service.accessCallback(context.Background(), nil, menuCallbackUpdate(testOwnerID, "access:revoke:200", "revoke", 1100))
			if _, ok := store.Get(200); ok {
				t.Fatal("revoke did not remove approved user")
			}
			before := len(client.snapshotOperations())

			handler.call(service, menuCallbackUpdate(200, handler.data, "stale", 1101))

			operations := client.snapshotOperations()
			if len(operations) != before+1 || operations[before].method != "answer" {
				t.Fatalf("operations after stale callback = %#v, want one additional acknowledgement", operations)
			}
			if len(client.snapshotDeletes()) != 0 || len(client.snapshotSends()) != 0 || len(client.snapshotDrafts()) != 0 || len(client.snapshotEdits()) != 0 {
				t.Fatalf("stale callback produced Telegram updates: operations=%#v", operations[before:])
			}
			if got := controller.logCallCount(); got != 0 {
				t.Fatalf("stale callback read logs %d times", got)
			}
			service.logStreams.mu.Lock()
			streamCount := len(service.logStreams.streams)
			service.logStreams.mu.Unlock()
			if streamCount != 0 {
				t.Fatalf("stale callback left %d log streams", streamCount)
			}
		})
	}
}
