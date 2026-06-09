package vpn

import (
	"bytes"
	"reflect"
	"testing"
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

type bufferWriteCloser struct {
	bytes.Buffer
}

func (b *bufferWriteCloser) Close() error {
	return nil
}
