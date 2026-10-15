package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditLog appends one JSON line per verified operation to a file, so that a
// workspace can tell what each authorized key ran. Every line carries the
// standard event envelope (timestamp, type, event_id, source) plus the key's
// fingerprint and the operation's own fields. The file is not immutable: it is
// evidence for catching mistakes, not a tamper-proof record.
type AuditLog struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

const auditEventSource = "owner_exec"

// NewAuditLog returns a log writing to path, or nil (a no-op) for "".
func NewAuditLog(path string, now func() time.Time) *AuditLog {
	if path == "" {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &AuditLog{path: path, now: now}
}

// Record appends one event. A nil log records nothing; a write failure is
// logged and never fails the operation it describes.
func (a *AuditLog) Record(eventType string, keyID string, fields map[string]any) {
	if a == nil {
		return
	}
	event := map[string]any{
		"timestamp": nanosecondTimestamp(a.now().UTC()),
		"type":      eventType,
		"event_id":  "evt-" + randomHex(16),
		"source":    auditEventSource,
		"keyid":     keyID,
	}
	for key, value := range fields {
		event[key] = value
	}
	line, err := json.Marshal(event)
	if err != nil {
		log.Printf("owner-exec: could not encode audit event %s: %v", eventType, err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.path), 0o755); err != nil {
		log.Printf("owner-exec: could not create the audit log directory: %v", err)
		return
	}
	file, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		log.Printf("owner-exec: could not open the audit log: %v", err)
		return
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		log.Printf("owner-exec: could not append to the audit log: %v", err)
	}
}

func nanosecondTimestamp(t time.Time) string {
	return fmt.Sprintf("%s.%09dZ", t.Format("2006-01-02T15:04:05"), t.Nanosecond())
}

func randomHex(byteCount int) string {
	buffer := make([]byte, byteCount)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buffer)
}
