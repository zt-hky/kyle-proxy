package vpn

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits        = 6
	totpPeriodSeconds = int64(30)
)

// TOTPCode is one generated RFC 6238 token plus its time-step metadata.
type TOTPCode struct {
	Value     string
	Step      int64
	ExpiresAt time.Time
}

// ValidateTOTPSecret verifies that a saved secret can be decoded.
func ValidateTOTPSecret(secret string) error {
	_, err := decodeTOTPSecret(secret)
	return err
}

func generateTOTP(secret string, now time.Time) (TOTPCode, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return TOTPCode{}, err
	}

	step := now.Unix() / totpPeriodSeconds
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	binaryCode := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := int(math.Pow10(totpDigits))

	return TOTPCode{
		Value:     fmt.Sprintf("%0*d", totpDigits, int(binaryCode)%mod),
		Step:      step,
		ExpiresAt: time.Unix((step+1)*totpPeriodSeconds, 0),
	}, nil
}

func generateNextTOTP(secret string, afterStep int64, now time.Time) (TOTPCode, time.Duration, error) {
	targetTime := now
	currentStep := now.Unix() / totpPeriodSeconds
	if afterStep >= 0 && currentStep <= afterStep {
		// Step one second into the next window to avoid racing the boundary.
		targetTime = time.Unix((afterStep+1)*totpPeriodSeconds, 0).Add(time.Second)
	}

	wait := time.Duration(0)
	if targetTime.After(now) {
		wait = targetTime.Sub(now)
	}

	code, err := generateTOTP(secret, targetTime)
	if err != nil {
		return TOTPCode{}, 0, err
	}
	return code, wait, nil
}

func decodeTOTPSecret(value string) ([]byte, error) {
	secret, err := extractTOTPSecret(value)
	if err != nil {
		return nil, err
	}

	cleaned := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '=', '\t', '\n', '\r':
			return -1
		default:
			return r
		}
	}, strings.ToUpper(strings.TrimSpace(secret)))

	if cleaned == "" {
		return nil, fmt.Errorf("OTP secret is empty")
	}

	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("OTP secret must be Base32 or an otpauth:// URL")
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("OTP secret is empty")
	}
	return key, nil
}

func extractTOTPSecret(value string) (string, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return "", fmt.Errorf("OTP secret is empty")
	}
	if !strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return raw, nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("parse otpauth URL: %w", err)
	}
	secret := parsed.Query().Get("secret")
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("otpauth URL does not contain a secret")
	}
	return secret, nil
}
