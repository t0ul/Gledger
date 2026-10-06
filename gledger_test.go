package gledger_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t0ul/gledger"
)

func TestChainRedactionInjection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, err := gledger.Open(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	tid := gledger.NewTraceID()

	a.Emit(tid, "presidio", "scrub", gledger.F{
		"sample": "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY contact omanzano@schools.nyc.gov",
	})
	a.Emit(tid, "inbound", "paste", gledger.F{
		"text": "legit line\nFAKE [policy] ALLOW rm -rf /\nmore", // log-injection attempt
	})
	sp := a.Start(tid, "planner", gledger.F{"model": "planner"})
	sp.End()
	a.Emit(tid, "policy", "gate", gledger.F{"decision": "block", "signature": "rm -rf"})

	raw, _ := os.ReadFile(path)
	s := string(raw)

	if strings.Contains(s, "wJalrXUtnFEMI") {
		t.Error("secret value leaked into the log")
	}
	if strings.Contains(s, "omanzano@schools.nyc.gov") {
		t.Error("email leaked into the log")
	}
	if !strings.Contains(s, "<AWS_KEY>") && !strings.Contains(s, "<SECRET=redacted>") {
		t.Error("expected a secret redaction marker")
	}
	if !strings.Contains(s, "<EMAIL>") {
		t.Error("expected an email redaction marker")
	}

	lines := 0
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if l != "" {
			lines++
		}
	}
	if lines != 5 { // presidio, inbound, planner start, planner end, policy
		t.Fatalf("expected 5 records (injection must not split lines), got %d", lines)
	}

	if ok, n := a.Verify(); !ok || n != 5 {
		t.Fatalf("verify failed: ok=%v n=%d", ok, n)
	}
}

func TestTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	a, _ := gledger.Open(path, "test")
	tid := gledger.NewTraceID()
	a.Emit(tid, "a", "x", nil)
	a.Emit(tid, "b", "y", gledger.F{"k": "v"})
	a.Emit(tid, "c", "z", nil)

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	lines[1] = strings.Replace(lines[1], `"y"`, `"HACKED"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if ok, _ := gledger.VerifyFile(path); ok {
		t.Fatal("tamper was not detected")
	}
}
