package vpn

import (
	"testing"
	"time"
)

func TestGenerateTOTPUsesRFC6238Algorithm(t *testing.T) {
	code, err := generateTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if err != nil {
		t.Fatalf("generateTOTP failed: %v", err)
	}
	if code.Value != "287082" {
		t.Fatalf("generateTOTP = %q, want RFC 6238 6-digit token %q", code.Value, "287082")
	}
	if code.Step != 1 {
		t.Fatalf("step = %d, want 1", code.Step)
	}
}

func TestGenerateNextTOTPWaitsForNextWindow(t *testing.T) {
	now := time.Unix(59, 500_000_000)
	code, wait, err := generateNextTOTP("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 1, now)
	if err != nil {
		t.Fatalf("generateNextTOTP failed: %v", err)
	}
	if code.Step != 2 {
		t.Fatalf("step = %d, want next step 2", code.Step)
	}
	wantWait := 1500 * time.Millisecond
	if wait != wantWait {
		t.Fatalf("wait = %s, want %s", wait, wantWait)
	}
}

func TestValidateTOTPSecretAcceptsOtpauthURL(t *testing.T) {
	err := ValidateTOTPSecret("otpauth://totp/VPN:user?secret=GEZDGNBVGY3TQOJQ&issuer=VPN")
	if err != nil {
		t.Fatalf("ValidateTOTPSecret failed for otpauth URL: %v", err)
	}
}

func TestValidateTOTPSecretRejectsInvalidSecret(t *testing.T) {
	if err := ValidateTOTPSecret("not a base32 secret!!!"); err == nil {
		t.Fatal("ValidateTOTPSecret accepted invalid secret")
	}
}
