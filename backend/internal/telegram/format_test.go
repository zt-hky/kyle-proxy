package telegram

import (
	"encoding/xml"
	"errors"
	"html"
	"io"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"globalprotect-manager/internal/vpn"
)

func TestFormatEscapesEveryDynamicField(t *testing.T) {
	hostile := `</code><script data-x="1">PWN</script><u>&"'</u>`
	escaped := html.EscapeString(hostile)
	upperEscaped := html.EscapeString(strings.ToUpper(hostile))

	tests := []struct {
		name string
		got  string
		want []string
	}{
		{
			name: "status",
			got: formatStatus(vpn.Status{
				State: hostileState(hostile), Phase: hostile, Detail: hostile,
				Interface: hostile, IP: hostile, Since: hostile, Error: hostile,
			}),
			want: []string{upperEscaped, escaped},
		},
		{
			name: "access request",
			got: formatAccessRequest(AccessRecord{
				UserID: 42, DisplayName: hostile, Username: hostile,
			}),
			want: []string{escaped, "@" + escaped},
		},
		{
			name: "access records",
			got: formatAccessRecords([]AccessRecord{{
				UserID: 42, DisplayName: hostile, Username: hostile, Status: AccessStatus(hostile),
			}}),
			want: []string{escaped, "@" + escaped},
		},
		{
			name: "event",
			got: formatEvent(vpn.Event{
				Kind: vpn.EventKind(hostile), Name: hostile, Outcome: hostile, Detail: hostile,
			}),
			want: []string{upperEscaped, escaped},
		},
		{
			name: "action error",
			got:  formatActionError(hostile, errors.New(hostile)),
			want: []string{escaped},
		},
		{
			name: "logs",
			got:  formatLogs([]string{hostile}, false),
			want: []string{escaped},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertValidTelegramHTML(t, tt.got)
			for _, want := range tt.want {
				if !strings.Contains(tt.got, want) {
					t.Errorf("formatted output does not contain escaped value %q: %q", want, tt.got)
				}
			}
			if strings.Contains(tt.got, "<script") || strings.Contains(tt.got, "<u>") {
				t.Fatalf("formatted output contains an injected tag: %q", tt.got)
			}
		})
	}
}

func TestFormatVisibleLengthUsesUTF16Limit(t *testing.T) {
	astral := strings.Repeat("😀", 3000)
	tests := []struct {
		name string
		got  string
	}{
		{"status", formatStatus(vpn.Status{State: vpn.StateConnected, Detail: astral})},
		{"access request", formatAccessRequest(AccessRecord{UserID: 7, DisplayName: astral})},
		{"access records", formatAccessRecords([]AccessRecord{{UserID: 7, DisplayName: astral, Status: AccessApproved}})},
		{"event", formatEvent(vpn.Event{Kind: vpn.EventKindState, Name: astral})},
		{"action error", formatActionError(astral, errors.New(astral))},
		{"logs", formatLogs([]string{astral}, false)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			visible, _ := assertValidTelegramHTML(t, tt.got)
			if units := len(utf16.Encode([]rune(visible))); units > telegramTextLimit {
				t.Fatalf("visible UTF-16 length = %d, want <= %d", units, telegramTextLimit)
			}
			if !utf8.ValidString(tt.got) {
				t.Fatal("formatter split an encoded rune")
			}
		})
	}
}

func TestFormatTemplatesAreBalanced(t *testing.T) {
	outputs := []string{
		formatStatus(vpn.Status{State: vpn.StateConnected, AwaitingOTP: true, AutoOTP: true, AutoReconnect: true, ReconnectAttempt: 2}),
		formatAccessRequest(AccessRecord{UserID: 4, DisplayName: "A", Username: "a"}),
		formatAccessRecords([]AccessRecord{{UserID: 4, DisplayName: "A", Username: "a", Status: AccessPending}}),
		formatAccessDecision(AccessApproved),
		formatEvent(vpn.Event{Kind: vpn.EventKindAction, Name: "connect", Outcome: "ok", Detail: "done"}),
		formatActionError("connect", errors.New("failed")),
		formatOTPError(),
		formatOTPPrompt("next"),
		formatLogs([]string{"one", "two"}, true),
	}
	for i, output := range outputs {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assertValidTelegramHTML(t, output)
		})
	}
}

func TestFormatLogsKeepsNewestTailWhenOversized(t *testing.T) {
	newest := strings.Repeat("😀<&", 2000) + "NEWEST-TAIL😀<&"
	got := formatLogs([]string{"oldest-secret", "middle-secret", newest}, false)
	visible, pre := assertValidTelegramHTML(t, got)

	if strings.Contains(pre, "oldest-secret") || strings.Contains(pre, "middle-secret") {
		t.Fatalf("oversized logs retained older lines: %q", pre)
	}
	if !strings.HasSuffix(pre, "NEWEST-TAIL😀<&") {
		t.Fatalf("newest log tail was not retained intact: suffix %q", tailForFailure(pre, 40))
	}
	if !strings.Contains(got, "&lt;&amp;") {
		t.Fatalf("newest tail was not escaped as a complete entity: %q", tailForFailure(got, 80))
	}
	if !strings.Contains(visible, "Older lines omitted.") {
		t.Fatalf("missing omission marker: %q", got)
	}
	if units := len(utf16.Encode([]rune(visible))); units > telegramTextLimit {
		t.Fatalf("visible UTF-16 length = %d, want <= %d", units, telegramTextLimit)
	}
	if !utf8.ValidString(got) {
		t.Fatal("oversized logs contain a split rune")
	}
}

func TestFormatAccessRecordsSortsDeterministicallyAndCountsOmitted(t *testing.T) {
	records := []AccessRecord{
		{UserID: 30, DisplayName: "Thirty", Status: AccessDenied},
		{UserID: 10, DisplayName: "Ten", Status: AccessApproved},
		{UserID: 20, DisplayName: strings.Repeat("😀", 3000), Status: AccessPending},
	}

	got := formatAccessRecords(records)
	if again := formatAccessRecords(records); again != got {
		t.Fatalf("formatting is nondeterministic:\nfirst:  %q\nsecond: %q", got, again)
	}
	assertValidTelegramHTML(t, got)
	if !strings.Contains(got, "<code>10</code>") {
		t.Fatalf("lowest sorted record is missing: %q", got)
	}
	if strings.Contains(got, "<code>20</code>") || strings.Contains(got, "<code>30</code>") {
		t.Fatalf("records after the oversized entry should be omitted: %q", got)
	}
	if !strings.Contains(got, "<i>2 more records omitted.</i>") {
		t.Fatalf("omitted record count is wrong: %q", got)
	}
	if records[0].UserID != 30 || records[1].UserID != 10 || records[2].UserID != 20 {
		t.Fatalf("formatter mutated caller order: %+v", records)
	}

	sortable := []AccessRecord{
		{UserID: 3, DisplayName: "C", Status: AccessPending},
		{UserID: 1, DisplayName: "A", Status: AccessPending},
		{UserID: 2, DisplayName: "B", Status: AccessPending},
	}
	sorted := formatAccessRecords(sortable)
	one := strings.Index(sorted, "<code>1</code>")
	two := strings.Index(sorted, "<code>2</code>")
	three := strings.Index(sorted, "<code>3</code>")
	if !(0 <= one && one < two && two < three) {
		t.Fatalf("records are not sorted by Telegram ID: %q", sorted)
	}
}

func TestFormatEmptyAndOptionalFieldsExact(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{"empty status", formatStatus(vpn.Status{}), "<b>GlobalProtect</b>\n<b>Status:</b> <code></code>"},
		{"empty access request", formatAccessRequest(AccessRecord{}), "<b>Access request</b>\n<b>User:</b> \n<b>Telegram ID:</b> <code>0</code>"},
		{"empty access records", formatAccessRecords(nil), "<b>Telegram access</b>\n<i>No access records.</i>"},
		{"empty event", formatEvent(vpn.Event{}), "<b>GlobalProtect event</b>\n<b>Type:</b> <code></code>\n<b>Name:</b> "},
		{"nil action error", formatActionError("connect", nil), "<b>Connect failed</b>\n<code>Unknown error.</code>"},
		{"otp error", formatOTPError(), "<b>OTP failed</b>\nThe one-time password was not accepted."},
		{"initial otp prompt", formatOTPPrompt("hostile-adapter<otp-secret>"), "<b>GlobalProtect OTP required</b>\nReply with the initial one-time password within <b>2 minutes</b>. Your reply will be deleted after it is claimed."},
		{"next otp prompt", formatOTPPrompt("next"), "<b>GlobalProtect OTP required</b>\nReply with the next one-time password within <b>2 minutes</b>. Your reply will be deleted after it is claimed."},
		{"empty live logs", formatLogs(nil, false), "<b>Live GlobalProtect logs</b>\n<i>No logs yet.</i>"},
		{"empty stopped logs", formatLogs(nil, true), "<b>GlobalProtect logs · stopped</b>\n<i>No logs yet.</i>"},
		{"approved access", formatAccessDecision(AccessApproved), "<b>Access</b>\nYour access request was approved."},
		{"denied access", formatAccessDecision(AccessDenied), "<b>Access</b>\nYour access request was denied."},
		{"pending access", formatAccessDecision(AccessPending), "<b>Access</b>\nYour access request is pending owner approval."},
		{"unknown access", formatAccessDecision(AccessStatus("injected-secret")), "<b>Access</b>\nYour access request status is unknown."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("formatted output = %q, want %q", tt.got, tt.want)
			}
			assertValidTelegramHTML(t, tt.got)
		})
	}
}

func TestFormatOTPErrorDoesNotExposeAdapterOrOTPContent(t *testing.T) {
	got := formatOTPError()
	for _, secret := range []string{"hostile-adapter-error", "123456", "<otp-secret>"} {
		if strings.Contains(got, secret) {
			t.Fatalf("OTP error exposed adapter or OTP content %q: %q", secret, got)
		}
	}
	if got != "<b>OTP failed</b>\nThe one-time password was not accepted." {
		t.Fatalf("OTP error = %q", got)
	}
}

func hostileState(value string) vpn.State {
	return vpn.State(value)
}

func assertValidTelegramHTML(t *testing.T, formatted string) (visible, pre string) {
	t.Helper()
	decoder := xml.NewDecoder(strings.NewReader("<root>" + formatted + "</root>"))
	allowed := map[string]bool{"root": true, "b": true, "i": true, "code": true, "pre": true}
	inPre := false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("invalid or unbalanced HTML template %q: %v", formatted, err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if !allowed[token.Name.Local] || len(token.Attr) != 0 {
				t.Fatalf("untrusted tag or attribute <%s> in %q", token.Name.Local, formatted)
			}
			if token.Name.Local == "pre" {
				inPre = true
			}
		case xml.EndElement:
			if token.Name.Local == "pre" {
				inPre = false
			}
		case xml.CharData:
			text := string(token)
			visible += text
			if inPre {
				pre += text
			}
		}
	}
	return visible, pre
}

func tailForFailure(value string, runes int) string {
	decoded := []rune(value)
	if len(decoded) <= runes {
		return value
	}
	return string(decoded[len(decoded)-runes:])
}
