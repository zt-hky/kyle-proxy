package vpn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOTPInputs(t *testing.T) {
	tests := []struct {
		name string
		otp  string
		otp2 string
		want []string
	}{
		{
			name: "empty",
		},
		{
			name: "single token is only sent once",
			otp:  "111111",
			want: []string{"111111"},
		},
		{
			name: "second token overrides reuse",
			otp:  "111111",
			otp2: "222222",
			want: []string{"111111", "222222"},
		},
		{
			name: "combined tokens are split",
			otp:  "111111, 222222\n333333",
			want: []string{"111111", "222222", "333333"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := otpInputs(tt.otp, tt.otp2)
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("otpInputs(%q, %q) = %#v, want %#v", tt.otp, tt.otp2, got, tt.want)
			}
		})
	}
}

func TestVPNEstablishedLineDetection(t *testing.T) {
	falsePositives := []string{
		"connected to 14.238.93.22:443",
		"connected to https on 14.238.93.22 with ciphersuite tls1.3",
		"ssl negotiation with 14.238.93.22",
	}
	for _, line := range falsePositives {
		if isVPNEstablishedLine(line) {
			t.Fatalf("isVPNEstablishedLine(%q) = true, want false", line)
		}
	}

	truePositives := []string{
		"esp session established with server",
		"vpn connection established",
		"connected as 10.1.2.3, using ssl",
		"configured as 10.1.2.3, with ssl connected",
	}
	for _, line := range truePositives {
		if !isVPNEstablishedLine(line) {
			t.Fatalf("isVPNEstablishedLine(%q) = false, want true", line)
		}
	}
}

func TestVPNInterfaceNameDetection(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{name: "tun0", want: true},
		{name: "tun12", want: true},
		{name: "gpd-0", want: true},
		{name: "utun4", want: true},
		{name: "tunl0", want: false},
		{name: "eth0", want: false},
	}

	for _, tt := range tests {
		if got := isVPNInterfaceName(tt.name); got != tt.want {
			t.Fatalf("isVPNInterfaceName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCredentialPromptDoesNotRequestOTP(t *testing.T) {
	stdin := &bufferWriteCloser{}
	m := NewManager()
	m.mu.Lock()
	m.state = StateConnecting
	m.stdin = stdin
	m.savedPassword = "saved-password"
	m.mu.Unlock()

	m.noteCredentialPrompt()
	if status := m.GetStatus(); status.AwaitingOTP || status.OTPPromptCount != 0 {
		t.Fatalf("portal credential prompt requested OTP: %#v", status)
	}

	m.noteCredentialPrompt()
	if status := m.GetStatus(); status.AwaitingOTP || status.OTPPromptCount != 0 {
		t.Fatalf("gateway credential prompt requested OTP: %#v", status)
	}
	if got := stdin.String(); got != "saved-password\n" {
		t.Fatalf("gateway password write = %q, want saved password once", got)
	}

	m.noteCredentialPrompt()
	if status := m.GetStatus(); status.AwaitingOTP || status.OTPPromptCount != 0 {
		t.Fatalf("repeated credential prompt requested OTP: %#v", status)
	}
	if got := stdin.String(); got != "saved-password\n" {
		t.Fatalf("repeated gateway prompt write = %q, want saved password once", got)
	}
}

func TestSubmitOTPRequiresOTPPrompt(t *testing.T) {
	stdin := &bufferWriteCloser{}
	m := NewManager()
	m.mu.Lock()
	m.state = StateConnecting
	m.stdin = stdin
	m.mu.Unlock()

	if err := m.SubmitOTP("123456"); err == nil {
		t.Fatal("SubmitOTP succeeded before an OTP prompt")
	}
	if got := stdin.String(); got != "" {
		t.Fatalf("SubmitOTP wrote %q before an OTP prompt", got)
	}

	m.mu.Lock()
	m.awaitingOTP = true
	m.otpPromptCount = 1
	m.mu.Unlock()

	if err := m.SubmitOTP("123456"); err != nil {
		t.Fatalf("SubmitOTP after OTP prompt failed: %v", err)
	}
	if got := stdin.String(); got != "123456\n" {
		t.Fatalf("SubmitOTP write = %q, want OTP line", got)
	}
}

func TestObservedDisconnectDoesNotCancelAutoReconnect(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.state = StateDisconnected
	m.mu.Unlock()

	if m.isStopped() {
		t.Fatal("observed disconnected state was treated as an intentional stop")
	}

	m.mu.Lock()
	m.stopRequested = true
	m.mu.Unlock()
	if !m.isStopped() {
		t.Fatal("explicit disconnect request did not stop reconnect")
	}
}

func TestEstablishedTunnelExitIsReconnectableAfterDisconnectedLine(t *testing.T) {
	processErr := errors.New("exit status 1")
	err := classifyOpenConnectExit(processErr, StateDisconnected, true, false)
	if !isReconnectableError(err) {
		t.Fatalf("established tunnel exit was not reconnectable: %v", err)
	}
	if !errors.Is(err, processErr) {
		t.Fatalf("reconnectable exit did not wrap process result: %v", err)
	}
}

func TestRequestedDisconnectIsNotReconnectable(t *testing.T) {
	err := classifyOpenConnectExit(errors.New("signal: terminated"), StateDisconnecting, true, true)
	if err != nil {
		t.Fatalf("requested disconnect returned an error: %v", err)
	}
}

func TestEventQueueIsMonotonicFIFOWithSlowConsumer(t *testing.T) {
	const eventCount = 256

	m := NewManager()
	events := make(chan Event, eventCount)
	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	callbackReleased := false
	defer func() {
		if !callbackReleased {
			close(releaseCallback)
		}
	}()

	m.OnEvent(func(event Event) {
		_ = m.GetStatus()
		if event.ID == 1 {
			close(callbackStarted)
			<-releaseCallback
		}
		events <- event
	})

	m.setPhase("phase-0", "detail-0")
	waitForSignal(t, callbackStarted, "first event callback")

	secondQueued := make(chan struct{})
	go func() {
		m.setPhase("phase-1", "detail-1")
		close(secondQueued)
	}()
	waitForSignal(t, secondQueued, "event enqueue while callback was blocked")

	for i := 2; i < eventCount; i++ {
		m.setPhase(fmt.Sprintf("phase-%d", i), fmt.Sprintf("detail-%d", i))
	}

	close(releaseCallback)
	callbackReleased = true
	for i := 1; i <= eventCount; i++ {
		event := receiveManagerEvent(t, events)
		if event.ID != uint64(i) {
			t.Fatalf("event %d has ID %d, want %d", i, event.ID, i)
		}
		if event.Name != fmt.Sprintf("phase-%d", i-1) {
			t.Fatalf("event %d has name %q, want phase-%d", i, event.Name, i-1)
		}
	}
}

func TestStatePhaseDetailAndOTPPromptEventsAreDeduplicated(t *testing.T) {
	m := NewManager()
	events := make(chan Event, 8)
	m.OnEvent(func(event Event) {
		events <- event
	})

	m.setState(StateConnecting, "")
	m.setState(StateConnecting, "")
	m.setPhase("auth", "first detail")
	m.setPhase("auth", "first detail")
	m.setPhase("auth", "changed detail")
	m.setPhase("auth", "changed detail")
	m.noteOTPPrompt()
	m.noteOTPPrompt()

	m.mu.RLock()
	eventCount := m.eventSeq
	m.mu.RUnlock()
	if eventCount != 5 {
		t.Fatalf("emitted %d events, want 5 unique state/phase/detail/OTP events", eventCount)
	}

	want := []struct {
		kind   EventKind
		name   string
		detail string
	}{
		{kind: EventKindState, name: string(StateConnecting), detail: string(StateConnecting)},
		{kind: EventKindPhase, name: "auth", detail: "first detail"},
		{kind: EventKindPhase, name: "auth", detail: "changed detail"},
		{kind: EventKindPhase, name: "mfa", detail: sanitizeLogLine("Waiting for fresh OTP response #1")},
		{kind: EventKindOTP, name: "prompt", detail: sanitizeLogLine("Manual OTP prompt #1")},
	}
	for i, expected := range want {
		event := receiveManagerEvent(t, events)
		if event.ID != uint64(i+1) ||
			event.Kind != expected.kind ||
			event.Name != expected.name ||
			event.Detail != expected.detail {
			t.Fatalf("event %d = %#v, want kind=%q name=%q detail=%q", i+1, event, expected.kind, expected.name, expected.detail)
		}
	}
}

func TestActionEventOutcomesAndOrdering(t *testing.T) {
	t.Run("rejected then noop", func(t *testing.T) {
		m := NewManager()
		events := make(chan Event, 2)
		m.OnEvent(func(event Event) {
			events <- event
		})

		if err := m.SubmitOTP(""); err == nil {
			t.Fatal("empty OTP unexpectedly succeeded")
		}
		if err := m.Disconnect(); err != nil {
			t.Fatalf("disconnect from disconnected state failed: %v", err)
		}

		rejected := receiveManagerEvent(t, events)
		noOp := receiveManagerEvent(t, events)
		if rejected.ID != 1 || rejected.Kind != EventKindAction || rejected.Name != "submit_otp" || rejected.Outcome != "rejected" {
			t.Fatalf("rejected action event = %#v", rejected)
		}
		if noOp.ID != 2 || noOp.Kind != EventKindAction || noOp.Name != "disconnect" || noOp.Outcome != "noop" {
			t.Fatalf("no-op action event = %#v", noOp)
		}
	})

	t.Run("accepted precedes phase and failed", func(t *testing.T) {
		m := NewManager()
		m.mu.Lock()
		m.state = StateConnecting
		m.awaitingOTP = true
		m.stdin = errorWriteCloser{err: errors.New("write blocked")}
		m.phase = "mfa"
		m.detail = "Waiting for fresh OTP response #1"
		m.mu.Unlock()

		events := make(chan Event, 3)
		m.OnEvent(func(event Event) {
			events <- event
		})
		if err := m.SubmitOTP("946281"); err == nil {
			t.Fatal("SubmitOTP unexpectedly succeeded with a failing input stream")
		}

		accepted := receiveManagerEvent(t, events)
		phase := receiveManagerEvent(t, events)
		failed := receiveManagerEvent(t, events)
		if accepted.ID != 1 || accepted.Kind != EventKindAction || accepted.Name != "submit_otp" || accepted.Outcome != "accepted" {
			t.Fatalf("accepted action event = %#v", accepted)
		}
		if phase.ID != 2 || phase.Kind != EventKindPhase || phase.Name != "auth" {
			t.Fatalf("phase event after accepted action = %#v", phase)
		}
		if failed.ID != 3 || failed.Kind != EventKindAction || failed.Name != "submit_otp" || failed.Outcome != "failed" {
			t.Fatalf("failed action event = %#v", failed)
		}
	})

	t.Run("connect failure follows accepted state and phase", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		m := NewManager()
		events := make(chan Event, 8)
		m.OnEvent(func(event Event) {
			events <- event
		})

		if err := m.Connect(ConnectRequest{Portal: "vpn.invalid", Username: "tester"}); err != nil {
			t.Fatalf("Connect returned synchronous error: %v", err)
		}

		got := make([]Event, 0, 8)
		for {
			event := receiveManagerEvent(t, events)
			got = append(got, event)
			if event.Kind == EventKindState && event.Name == string(StateError) {
				break
			}
		}
		assertEventPrecedes(t, got,
			func(event Event) bool {
				return event.Kind == EventKindAction && event.Name == "connect" && event.Outcome == "accepted"
			},
			func(event Event) bool {
				return event.Kind == EventKindState && event.Name == string(StateConnecting)
			},
			"connect accepted", "connecting state",
		)
		assertEventPrecedes(t, got,
			func(event Event) bool {
				return event.Kind == EventKindAction && event.Name == "connect" && event.Outcome == "failed"
			},
			func(event Event) bool {
				return event.Kind == EventKindState && event.Name == string(StateError)
			},
			"connect failed", "error state",
		)
	})
}

func TestReconnectLifecycleEvents(t *testing.T) {
	t.Run("scheduled then cancelled", func(t *testing.T) {
		binDir := t.TempDir()
		openConnect := filepath.Join(binDir, "openconnect")
		script := "#!/bin/sh\necho 'VPN connection established'\nexit 1\n"
		if err := os.WriteFile(openConnect, []byte(script), 0o700); err != nil {
			t.Fatalf("write fake openconnect: %v", err)
		}
		t.Setenv("PATH", binDir)

		m := NewManager()
		m.mu.Lock()
		m.state = StateConnecting
		m.mu.Unlock()
		events := make(chan Event, 16)
		m.OnEvent(func(event Event) {
			if event.Kind == EventKindReconnect && event.Name == "scheduled" {
				m.mu.Lock()
				m.stopRequested = true
				m.mu.Unlock()
			}
			events <- event
		})

		err := m.runConnectLoop(ConnectRequest{
			Portal:        "vpn.invalid",
			Username:      "tester",
			OTPSecret:     "JBSWY3DPEHPK3PXP",
			AutoReconnect: true,
		})
		if err != nil {
			t.Fatalf("runConnectLoop after reconnect cancellation: %v", err)
		}

		got := receiveAllManagerEvents(t, m, events)
		reconnects := reconnectEvents(got)
		if len(reconnects) != 2 || reconnects[0].Name != "scheduled" || reconnects[1].Name != "cancelled" {
			t.Fatalf("reconnect events = %#v, want scheduled then cancelled", reconnects)
		}
		if reconnects[0].ID >= reconnects[1].ID {
			t.Fatalf("reconnect event IDs = %d, %d, want monotonic order", reconnects[0].ID, reconnects[1].ID)
		}
	})

	t.Run("started then established", func(t *testing.T) {
		m := NewManager()
		m.mu.Lock()
		m.state = StateConnecting
		m.reconnectAttempt = 2
		m.emitReconnectLocked("started", "Starting reconnect attempt 2")
		m.mu.Unlock()

		events := make(chan Event, 4)
		m.OnEvent(func(event Event) {
			events <- event
		})
		m.streamOutput(strings.NewReader("VPN connection established\n"))

		got := receiveAllManagerEvents(t, m, events)
		reconnects := reconnectEvents(got)
		if len(reconnects) != 2 || reconnects[0].Name != "started" || reconnects[1].Name != "established" {
			t.Fatalf("reconnect events = %#v, want started then established", reconnects)
		}
		if reconnects[0].ID >= reconnects[1].ID {
			t.Fatalf("reconnect event IDs = %d, %d, want monotonic order", reconnects[0].ID, reconnects[1].ID)
		}
	})
}

func TestEventJSONRedactsAllCredentialValues(t *testing.T) {
	const (
		passwordValue      = "password-value-8f12"
		otpValue           = "otp-value-4d23"
		totpValue          = "totp-value-9a34"
		cookieValue        = "cookie-value-5b45"
		authorizationValue = "authorization-value-6c56"
	)
	sensitiveLine := "password=" + passwordValue +
		" OTP=" + otpValue +
		" TOTP=" + totpValue +
		" Authorization: Bearer " + authorizationValue +
		" Cookie: " + cookieValue

	m := NewManager()
	m.mu.Lock()
	m.savedPassword = passwordValue
	m.otpSecret = totpValue
	m.lastLog = "Cookie: " + cookieValue
	m.mu.Unlock()
	m.setState(StateError, sensitiveLine)

	events := make(chan Event, 2)
	m.OnEvent(func(event Event) {
		events <- event
	})
	got := []Event{receiveManagerEvent(t, events), receiveManagerEvent(t, events)}
	serialized, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal events: %v", err)
	}
	for _, secret := range []string{
		passwordValue,
		otpValue,
		totpValue,
		cookieValue,
		authorizationValue,
	} {
		if bytes.Contains(serialized, []byte(secret)) {
			t.Fatalf("event JSON leaked sensitive value %q: %s", secret, serialized)
		}
	}
}

func receiveAllManagerEvents(t *testing.T, m *Manager, events <-chan Event) []Event {
	t.Helper()
	m.mu.RLock()
	count := m.eventSeq
	m.mu.RUnlock()
	got := make([]Event, 0, count)
	for i := uint64(0); i < count; i++ {
		got = append(got, receiveManagerEvent(t, events))
	}
	return got
}

func reconnectEvents(events []Event) []Event {
	result := make([]Event, 0, len(events))
	for _, event := range events {
		if event.Kind == EventKindReconnect {
			result = append(result, event)
		}
	}
	return result
}

func assertEventPrecedes(
	t *testing.T,
	events []Event,
	before, after func(Event) bool,
	beforeName, afterName string,
) {
	t.Helper()
	beforeIndex, afterIndex := -1, -1
	for i, event := range events {
		if beforeIndex == -1 && before(event) {
			beforeIndex = i
		}
		if afterIndex == -1 && after(event) {
			afterIndex = i
		}
	}
	if beforeIndex == -1 || afterIndex == -1 || beforeIndex >= afterIndex {
		t.Fatalf("%s index=%d, %s index=%d in events %#v", beforeName, beforeIndex, afterName, afterIndex, events)
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func receiveManagerEvent(t *testing.T, events <-chan Event) Event {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for VPN event")
		return Event{}
	}
}

type errorWriteCloser struct {
	err error
}

func (w errorWriteCloser) Write([]byte) (int, error) {
	return 0, w.err
}

func (errorWriteCloser) Close() error {
	return nil
}

type bufferWriteCloser struct {
	bytes.Buffer
}

func (b *bufferWriteCloser) Close() error {
	return nil
}
