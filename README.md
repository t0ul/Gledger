# gledger

Dependency-free, **tamper-evident** audit log for AI systems — the Go-native
telemetry spine of the fleet. Logs are only "truth" if the log is trustworthy.

- **One `trace_id` per request** — reconstruct and verify a whole request from one id.
- **Hash-chained JSONL** — each record chains the previous hash; altering any
  record breaks the chain (`Verify` / `gledger verify`).
- **Auto-redaction** — secrets (AWS keys, env assignments, tokens, JWTs, bearer)
  and emails are replaced with markers before writing. Log the event, never the value.
- **Log-injection defanging** — control chars/newlines in field values are
  neutralized, so untrusted input can't forge or split records.

## Use

```go
a, _ := gledger.Open("logs/audit.jsonl", "control-plane")
tid := gledger.NewTraceID()
sp := a.Start(tid, "planner", gledger.F{"model": "planner"}); defer sp.End()
a.Emit(tid, "policy", "gate", gledger.F{"decision": "block", "signature": "rm -rf"})
ok, n := a.Verify() // re-walk the chain
```

CLI:

```sh
gledger verify logs/audit.jsonl   # chain_ok=true records=N
```

Zero third-party dependencies (stdlib only). NER-grade redaction belongs behind a
served model; gledger ships the deterministic secret/PII recognizers inline.
