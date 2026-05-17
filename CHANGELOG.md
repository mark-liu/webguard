# Changelog

## 0.4.0 — 2026-05-17

### Security — audit log defang

Closes the "audit-log-as-backdoor" channel: any URL captured into
`~/.local/share/webguard-mcp/audit.jsonl` could previously re-enter Claude's
context as instructions when an operator `cat`'d the log or when
`webguard_report` aggregated recent activity. URLs are now defanged on
write so they're safe by construction for every downstream reader.

Defang transforms applied inside `audit::Logger::log`:

- `scheme://` becomes `scheme:⁄⁄` (U+2044 FRACTION SLASH ×2). Visually
  similar to `/`; rejected by strict URL parsers (reqwest, curl, browsers).
- Query string collapsed to `?[N params]` — the primary injection vector.
- Fragment stripped wholesale.
- Path word-runs (4+ ASCII-alphabetic chars) interleaved with U+00B7
  MIDDLE DOT to defeat path-based payloads like
  `/ignore-previous-instructions`. Host stays intact for forensics.
- `error` field is scanned for embedded URLs and each is defanged the
  same way (rquest/reqwest `Display` impls embed `... for url (...)`,
  so without this an attacker could persist a raw URL via a triggered
  fetch error).

New audit entry field: `host: String`. Extracted from the raw URL via
`Url::parse` *before* defanging, so `webguard_report`'s
"Blocked/warned domains" aggregation continues to work. Pre-0.4.0
entries (no `host` field) fall back to `Url::parse(&entry.url)`.

### Operator action required

Pre-0.4.0 audit log lines remain raw on disk. They are not migrated
automatically. After upgrading, truncate or rotate the log:

```
: > ~/.local/share/webguard-mcp/audit.jsonl
```

Or back up + remove if you need the history:

```
mv ~/.local/share/webguard-mcp/audit.jsonl{,.pre-0.4.0}
```

### Tests

22 unit tests in `src/audit.rs`, including end-to-end round-trip
canaries for the URL-write path, the `host` population, and the
error-field defang. Full suite: 122 tests, all passing.
