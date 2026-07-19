package vpn

import (
	"bytes"
	"errors"
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

func TestEventsAreFIFOAndCallbacksDoNotHoldManagerLock(t *testing.T) {
	m := NewManager()
	events := make(chan Event, 4)
	m.OnEvent(func(event Event) {
		_ = m.GetStatus()
		events <- event
	})

	m.setState(StateConnecting, "")
	m.setPhase("auth", "Waiting for authentication")
	m.setPhase("auth", "Waiting for authentication")

	first := receiveManagerEvent(t, events)
	second := receiveManagerEvent(t, events)
	if first.ID != 1 || second.ID != 2 {
		t.Fatalf("event IDs = %d, %d, want FIFO IDs 1, 2", first.ID, second.ID)
	}
	if first.Kind != EventKindState || first.Name != string(StateConnecting) {
		t.Fatalf("first event = %#v, want connecting state", first)
	}
	if second.Kind != EventKindPhase || second.Name != "auth" {
		t.Fatalf("second event = %#v, want auth phase", second)
	}
	select {
	case event := <-events:
		t.Fatalf("duplicate phase event = %#v", event)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestEventsQueuedBeforeCallbackRegistrationAndSanitized(t *testing.T) {
	m := NewManager()
	m.setState(StateError, "password=super-secret otp=123456")

	events := make(chan Event, 2)
	m.OnEvent(func(event Event) {
		events <- event
	})
	stateEvent := receiveManagerEvent(t, events)
	phaseEvent := receiveManagerEvent(t, events)
	for _, event := range []Event{stateEvent, phaseEvent} {
		serialized := event.Detail + event.Status.Error + event.Status.Detail + event.Status.LastLog
		if strings.Contains(serialized, "super-secret") || strings.Contains(serialized, "123456") {
			t.Fatalf("event leaked secret: %#v", event)
		}
	}
	if stateEvent.ID != 1 || phaseEvent.ID != 2 {
		t.Fatalf("queued event IDs = %d, %d, want 1, 2", stateEvent.ID, phaseEvent.ID)
	}
}

func TestActionEventsReportRejectedAndNoop(t *testing.T) {
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
	if rejected.Kind != EventKindAction || rejected.Name != "submit_otp" || rejected.Outcome != "rejected" {
		t.Fatalf("rejected action event = %#v", rejected)
	}
	if noOp.Kind != EventKindAction || noOp.Name != "disconnect" || noOp.Outcome != "noop" {
		t.Fatalf("no-op action event = %#v", noOp)
	}
}

func TestDuplicateOTPPromptEmitsOneOTPEvent(t *testing.T) {
	m := NewManager()
	m.mu.Lock()
	m.state = StateConnecting
	m.mu.Unlock()
	events := make(chan Event, 4)
	m.OnEvent(func(event Event) {
		events <- event
	})

	m.noteOTPPrompt()
	m.noteOTPPrompt()
	received := []Event{receiveManagerEvent(t, events), receiveManagerEvent(t, events)}
	otpCount := 0
	for _, event := range received {
		if event.Kind == EventKindOTP {
			otpCount++
			if event.Name != "prompt" {
				t.Fatalf("OTP event = %#v, want prompt", event)
			}
		}
	}
	if otpCount != 1 {
		t.Fatalf("OTP event count = %d, want one", otpCount)
	}
	select {
	case event := <-events:
		t.Fatalf("duplicate OTP prompt event = %#v", event)
	case <-time.After(50 * time.Millisecond):
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

type bufferWriteCloser struct {
	bytes.Buffer
}

func (b *bufferWriteCloser) Close() error {
	return nil
}
