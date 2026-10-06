// Package gledger is a dependency-free, tamper-evident audit log for AI systems:
// one correlation trace_id per request, hash-chained JSONL records, automatic
// redaction of secrets/PII, and log-injection defanging. "Logs are truth" only
// if the log itself is trustworthy — gledger makes it so. It is the Go-native
// sibling of the Python telemetry spine; part of the fleet.
package gledger

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// F is a convenience alias for structured fields.
type F = map[string]any

var redactions = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(?i)\b\w*(?:secret|passwd|password|token|apikey|api[_-]?key|access[_-]?key|credential|private[_-]?key)\w*\s*=\s*\S+`), "<SECRET=redacted>"},
	{regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b`), "<AWS_KEY>"},
	{regexp.MustCompile(`\b(?:sk|pk|rk|ghp|gho|ghs|xox[baprs])[-_][A-Za-z0-9]{16,}\b`), "<TOKEN>"},
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`), "<JWT>"},
	{regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._\-]{10,}\b`), "<BEARER>"},
	{regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), "<EMAIL>"},
}

var ctrlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

const maxVal = 2000

func cleanString(s string) string {
	for _, r := range redactions {
		s = r.re.ReplaceAllString(s, r.with)
	}
	s = ctrlChars.ReplaceAllString(s, " ") // defang log injection: no raw newlines/CR/control
	if len(s) > maxVal {
		s = s[:maxVal] + "…"
	}
	return s
}

func cleanValue(v any) any {
	switch t := v.(type) {
	case string:
		return cleanString(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = cleanValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = cleanValue(vv)
		}
		return out
	default:
		return v
	}
}

// NewTraceID returns a random 128-bit hex correlation id.
func NewTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AuditLog is an append-only, hash-chained JSONL log.
type AuditLog struct {
	path    string
	service string
	mu      sync.Mutex
	prev    string
}

// Open returns an AuditLog writing to path, continuing any existing chain.
func Open(path, service string) (*AuditLog, error) {
	if dir := dirOf(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	a := &AuditLog{path: path, service: service}
	a.prev = a.lastHash()
	return a, nil
}

func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

func (a *AuditLog) lastHash() string {
	f, err := os.Open(a.path)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	last := ""
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			last = t
		}
	}
	if last == "" {
		return ""
	}
	var rec map[string]any
	if json.Unmarshal([]byte(last), &rec) != nil {
		return ""
	}
	h, _ := rec["hash"].(string)
	return h
}

// Emit writes one record under traceID and returns its hash.
func (a *AuditLog) Emit(traceID, span, event string, fields F) string {
	if fields == nil {
		fields = F{}
	}
	core := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"trace_id": traceID,
		"service":  a.service,
		"span":     span,
		"event":    event,
		"fields":   cleanValue(map[string]any(fields)),
	}
	// Normalize via a JSON round-trip so the bytes hashed on Emit are byte-identical
	// to what Verify reconstructs from disk (no numeric/type drift).
	body := canonical(core)

	a.mu.Lock()
	defer a.mu.Unlock()
	prev := a.prev
	digest := chain(prev, body)

	var rec map[string]any
	_ = json.Unmarshal([]byte(body), &rec)
	rec["prev"] = prev
	rec["hash"] = digest
	line := marshal(rec)
	if f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
		_, _ = f.Write(append(line, '\n'))
		_ = f.Close()
	}
	a.prev = digest
	fmt.Printf("🧾 [%s] %s trace=%s\n", span, event, shortID(traceID))
	return digest
}

// marshal serializes v to JSON WITHOUT Go's default HTML escaping, so redaction
// markers like <EMAIL> stay literal in the log instead of becoming \u003cEMAIL\u003e.
// Used everywhere bytes are hashed or written, so the chain stays byte-consistent.
func marshal(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	b := buf.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return b
}

func canonical(v map[string]any) string {
	raw := marshal(v)
	var norm map[string]any
	_ = json.Unmarshal(raw, &norm)
	out := marshal(norm)
	return string(out)
}

func chain(prev, body string) string {
	sum := sha256.Sum256([]byte(prev + body))
	return hex.EncodeToString(sum[:])
}

func shortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// Verify re-walks the hash chain. Returns (ok, recordsChecked).
func (a *AuditLog) Verify() (bool, int) { return verifyPath(a.path) }

// VerifyFile checks a chain without opening a writer (no side effects).
func VerifyFile(path string) (bool, int) { return verifyPath(path) }

func verifyPath(path string) (bool, int) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, 0
		}
		return false, 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	prev, n := "", 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil {
			return false, n
		}
		storedPrev, _ := rec["prev"].(string)
		storedHash, _ := rec["hash"].(string)
		delete(rec, "prev")
		delete(rec, "hash")
		body := marshal(rec)
		if storedPrev != prev || storedHash != chain(prev, string(body)) {
			return false, n
		}
		prev = storedHash
		n++
	}
	return true, n
}

// Span records a start event and, on End/Fail, an end event with duration.
type Span struct {
	a       *AuditLog
	traceID string
	name    string
	start   time.Time
}

// Start logs "start" and returns a Span; call End() (defer) to log "end".
func (a *AuditLog) Start(traceID, name string, fields F) *Span {
	a.Emit(traceID, name, "start", fields)
	return &Span{a: a, traceID: traceID, name: name, start: time.Now()}
}

// End logs a successful end with elapsed milliseconds.
func (s *Span) End() { s.finish("ok", nil) }

// Fail logs an errored end.
func (s *Span) Fail(err error) { s.finish("error", F{"error": err.Error()}) }

func (s *Span) finish(status string, extra F) {
	f := F{"status": status, "ms": time.Since(s.start).Milliseconds()}
	for k, v := range extra {
		f[k] = v
	}
	s.a.Emit(s.traceID, s.name, "end", f)
}

var (
	defOnce sync.Once
	defLog  *AuditLog
)

// Default returns a process-wide AuditLog at $GLEDGER_LOG (default logs/audit.jsonl).
func Default() *AuditLog {
	defOnce.Do(func() {
		path := envOr("GLEDGER_LOG", "logs/audit.jsonl")
		defLog, _ = Open(path, envOr("GLEDGER_SERVICE", "app"))
	})
	return defLog
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
