package telegram

import (
	"html"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"globalprotect-manager/internal/vpn"
)

const telegramTextLimit = 4096

type htmlBuilder struct {
	strings.Builder
	visible int
}

func (b *htmlBuilder) remaining() int {
	return telegramTextLimit - b.visible
}

func (b *htmlBuilder) tag(tag string) {
	b.WriteString(tag)
}

func (b *htmlBuilder) text(value string) bool {
	bounded := truncateUTF16(value, b.remaining())
	b.WriteString(html.EscapeString(bounded))
	b.visible += utf16Units(bounded)
	return len(bounded) == len(value)
}

func (b *htmlBuilder) bold(value string) bool {
	b.tag("<b>")
	complete := b.text(value)
	b.tag("</b>")
	return complete
}

func (b *htmlBuilder) italic(value string) bool {
	b.tag("<i>")
	complete := b.text(value)
	b.tag("</i>")
	return complete
}

func (b *htmlBuilder) code(value string) bool {
	b.tag("<code>")
	complete := b.text(value)
	b.tag("</code>")
	return complete
}

func (b *htmlBuilder) field(label, value string, code bool) bool {
	prefixUnits := 2 + utf16Units(label) // newline, label, and separating space
	if b.remaining() < prefixUnits {
		return false
	}
	b.text("\n")
	b.bold(label)
	b.text(" ")
	if code {
		return b.code(value)
	}
	return b.text(value)
}

func utf16Units(value string) int {
	units := 0
	for _, r := range value {
		units++
		if r > 0xffff {
			units++
		}
	}
	return units
}

func truncateUTF16(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	units := 0
	for i, r := range value {
		n := 1
		if r > 0xffff {
			n = 2
		}
		if units+n > limit {
			return value[:i]
		}
		units += n
	}
	return value
}

func truncateUTF16Left(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	units := 0
	for end := len(value); end > 0; {
		r, size := utf8.DecodeLastRuneInString(value[:end])
		n := 1
		if r > 0xffff {
			n = 2
		}
		if units+n > limit {
			return value[end:]
		}
		units += n
		end -= size
	}
	return value
}

func formatStatus(status vpn.Status) string {
	var b htmlBuilder
	b.bold("GlobalProtect")
	b.field("Status:", strings.ToUpper(string(status.State)), true)
	if status.Phase != "" {
		b.field("Phase:", status.Phase, true)
	}
	if status.Detail != "" {
		b.field("Detail:", status.Detail, false)
	}
	if status.Interface != "" {
		b.field("Interface:", status.Interface, true)
	}
	if status.IP != "" {
		b.field("IP:", status.IP, true)
	}
	if status.Since != "" {
		b.field("Since:", status.Since, true)
	}
	if status.AwaitingOTP {
		b.field("OTP:", "Awaiting a one-time password", false)
	}
	if status.AutoOTP {
		b.field("Automatic OTP:", "Enabled", false)
	}
	if status.AutoReconnect {
		reconnect := "Enabled"
		if status.ReconnectAttempt > 0 {
			reconnect += " · attempt " + strconv.Itoa(status.ReconnectAttempt)
		}
		b.field("Reconnect:", reconnect, false)
	}
	if status.Error != "" {
		b.field("Error:", status.Error, false)
	}
	return b.String()
}

func formatAccessRequest(record AccessRecord) string {
	var b htmlBuilder
	b.bold("Access request")
	b.field("User:", record.DisplayName, false)
	b.field("Telegram ID:", strconv.FormatInt(record.UserID, 10), true)
	if record.Username != "" {
		b.field("Username:", "@"+record.Username, true)
	}
	return b.String()
}

func formatAccessRecords(records []AccessRecord) string {
	var b htmlBuilder
	b.bold("Telegram access")
	if len(records) == 0 {
		b.text("\n")
		b.italic("No access records.")
		return b.String()
	}

	sorted := slices.Clone(records)
	slices.SortFunc(sorted, func(a, c AccessRecord) int {
		return intCompare(a.UserID, c.UserID)
	})

	for i, record := range sorted {
		id := strconv.FormatInt(record.UserID, 10)
		status := string(record.Status)
		recordUnits := accessRecordUnits(record, id, status)
		remainingRecords := len(sorted) - i - 1
		reserve := 0
		if remainingRecords > 0 {
			reserve = accessOmissionUnits(remainingRecords)
		}
		if recordUnits+reserve > b.remaining() {
			appendAccessOmission(&b, len(sorted)-i)
			break
		}

		b.text("\n\n")
		b.bold("User:")
		b.text(" ")
		b.text(record.DisplayName)
		b.field("Telegram ID:", id, true)
		if record.Username != "" {
			b.field("Username:", "@"+record.Username, true)
		}
		b.field("Status:", status, true)
	}
	return b.String()
}

func intCompare(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

func accessRecordUnits(record AccessRecord, id, status string) int {
	units := utf16Units("\n\nUser: ") + utf16Units(record.DisplayName)
	units += utf16Units("\nTelegram ID: ") + utf16Units(id)
	if record.Username != "" {
		units += utf16Units("\nUsername: @") + utf16Units(record.Username)
	}
	return units + utf16Units("\nStatus: ") + utf16Units(status)
}

func accessOmissionUnits(count int) int {
	return utf16Units("\n") + len(strconv.Itoa(count)) + utf16Units(" more records omitted.")
}

func appendAccessOmission(b *htmlBuilder, count int) {
	b.text("\n")
	b.italic(strconv.Itoa(count) + " more records omitted.")
}

func formatAccessDecision(status AccessStatus) string {
	var b htmlBuilder
	b.bold("Access")
	b.text("\n")
	switch status {
	case AccessApproved:
		b.text("Your access request was approved.")
	case AccessDenied:
		b.text("Your access request was denied.")
	case AccessPending:
		b.text("Your access request is pending owner approval.")
	default:
		b.text("Your access request status is unknown.")
	}
	return b.String()
}

func formatEvent(event vpn.Event) string {
	var b htmlBuilder
	b.bold("GlobalProtect event")
	b.field("Type:", strings.ToUpper(string(event.Kind)), true)
	b.field("Name:", event.Name, false)
	if event.Outcome != "" {
		b.field("Outcome:", event.Outcome, true)
	}
	if event.Detail != "" {
		b.field("Detail:", event.Detail, false)
	}
	return b.String()
}

func formatActionError(action string, err error) string {
	if action == "connect" {
		action = "Connect"
	} else if action == "disconnect" {
		action = "Disconnect"
	}

	var b htmlBuilder
	b.bold(action + " failed")
	b.text("\n")
	message := "Unknown error."
	if err != nil {
		message = err.Error()
	}
	b.code(message)
	return b.String()
}

func formatOTPError() string {
	var b htmlBuilder
	b.bold("OTP failed")
	b.text("\nThe one-time password was not accepted.")
	return b.String()
}

func formatOTPPrompt(kind string) string {
	prompt := "Reply with the initial one-time password within "
	if kind == "next" {
		prompt = "Reply with the next one-time password within "
	}

	var b htmlBuilder
	b.bold("GlobalProtect OTP required")
	b.text("\n")
	b.text(prompt)
	b.bold("2 minutes")
	b.text(". Your reply will be deleted after it is claimed.")
	return b.String()
}

func formatLogs(lines []string, stopped bool) string {
	heading := "Live GlobalProtect logs"
	if stopped {
		heading = "GlobalProtect logs · stopped"
	}
	return formatStreamLines(heading, "No logs yet.", lines)
}

func formatEvents(events []vpn.Event, stopped bool) string {
	heading := "Live GlobalProtect events"
	if stopped {
		heading = "GlobalProtect events · idle"
	}
	lines := make([]string, len(events))
	for i, event := range events {
		var line strings.Builder
		if !event.At.IsZero() {
			line.WriteString(event.At.Format("15:04:05 "))
		}
		line.WriteByte('[')
		line.WriteString(strings.ToUpper(string(event.Kind)))
		line.WriteString("] ")
		line.WriteString(event.Name)
		if event.Outcome != "" {
			line.WriteString(" · ")
			line.WriteString(event.Outcome)
		}
		if event.Detail != "" {
			line.WriteString(" — ")
			line.WriteString(event.Detail)
		}
		lines[i] = line.String()
	}
	return formatStreamLines(heading, "No events yet.", lines)
}

func formatStreamLines(heading, empty string, lines []string) string {
	var b htmlBuilder
	b.bold(heading)
	if len(lines) == 0 {
		b.text("\n")
		b.italic(empty)
		return b.String()
	}

	contentUnits := 0
	allFit := true
	for i, line := range lines {
		if i > 0 {
			contentUnits++
		}
		contentUnits += utf16Units(line)
		if b.visible+1+contentUnits > telegramTextLimit {
			allFit = false
			break
		}
	}

	start := 0
	newest := lines[len(lines)-1]
	content := ""
	if allFit {
		content = strings.Join(lines, "\n")
	} else {
		const footer = "Older lines omitted."
		capacity := telegramTextLimit - b.visible - utf16Units("\n\n") - utf16Units(footer)
		newestUnits := utf16Units(newest)
		if newestUnits > capacity {
			content = truncateUTF16Left(newest, capacity)
			start = len(lines) - 1
		} else {
			start = len(lines) - 1
			used := newestUnits
			for start > 0 {
				previousUnits := utf16Units(lines[start-1])
				if used+1+previousUnits > capacity {
					break
				}
				used += 1 + previousUnits
				start--
			}
			content = strings.Join(lines[start:], "\n")
		}
	}

	b.text("\n")
	b.tag("<pre>")
	b.text(content)
	b.tag("</pre>")
	if !allFit || start > 0 {
		b.text("\n")
		b.italic("Older lines omitted.")
	}
	return b.String()
}
