# WebGuard

Secure web fetching MCP server for LLM agents. Scans fetched content for prompt injection attacks **before** it enters the LLM context window. Malicious content is blocked entirely — zero leaked tokens.

> Rust rewrite of [webguard-mcp (Go)](https://github.com/mark-liu/webguard-mcp). Same security model, same test suite, smaller binary, no GC pauses.

## What Changed (Go → Rust)

- **Binary**: 6MB vs 10MB
- **No garbage collector** — consistent sub-millisecond scan latency
- **BurntSushi's aho-corasick** — ripgrep-grade pattern matching
- **Streaming body reads** — size limit enforced during download, not after
- **Per-hop redirect SSRF validation** — each redirect re-checked against blocklists
- Same 38 built-in patterns, same two-stage cascade, same SSRF protection

## Install

```bash
# Homebrew (macOS/Linux)
brew install mark-liu/tap/webguard

# Cargo (from crates.io)
cargo install webguard

# From source
git clone https://github.com/mark-liu/webguard
cd webguard
cargo build --release
# Binary at target/release/webguard
```

## Usage

```bash
# Add to Claude Code
claude mcp add webguard -s user -- /path/to/webguard

# Then use webguard_fetch in Claude Code to retrieve any URL
```

## Architecture

```
Claude Code → webguard_fetch(url)
                    │
        ┌───────────┴───────────┐
        │ 1. URL Validation     │  SSRF prevention, scheme check
        │ 2. DNS Pinning        │  Resolve + validate all IPs
        │ 3. HTTP Fetch         │  HTTPS, streaming body, retry
        │ 4. Redirect Recheck   │  Re-validate SSRF on every hop
        │ 5. Content Extraction │  HTML → markdown, strip scripts
        │ 6. Preprocessing      │  Comment extraction, entity decode,
        │                       │  base64/URL/hex decode, NFC normalize,
        │                       │  zero-width strip
        │ 7. Stage 1: Patterns  │  Aho-Corasick + regex (~0.3ms)
        │    ↳ Category filter  │  Suppress per-domain categories
        │    ↳ Doc-path hints   │  Auto-suppress for /docs/, /api/
        │ 8. Stage 2: Heuristic │  Density, clustering, proximity
        │ 9. Decision           │  PASS/WARN/BLOCK based on mode
        │ 10. Audit Log         │  JSONL with pattern IDs + timing
        └───────────────────────┘
```

## Tools

### `webguard_fetch`

Fetches a URL with SSRF protection and prompt injection scanning.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | yes | URL to fetch (http/https) |
| `headers` | object | no | Custom HTTP headers |
| `raw` | boolean | no | Return raw HTML instead of markdown |
| `max_chars` | number | no | Truncate response to N characters (0 = unlimited) |

**On PASS**: returns extracted markdown content + metadata.
**On WARN** (mode=warn): returns content with a warning banner + metadata.
**On BLOCK** (mode=block, default): returns `[BLOCKED: prompt injection detected]` + metadata. Zero page content leaked.

### `webguard_status`

Returns server health: version, pattern count, mode, sensitivity, config.

### `webguard_report`

Returns an audit report aggregated from the JSONL audit log.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `days` | number | no | Number of days to include (default: 7) |

## Test Pages

Live test pages for verifying detection: https://mark-liu.github.io/webguard/test/

| Page | Expected | Category |
|------|----------|----------|
| [clean.html](https://mark-liu.github.io/webguard/test/clean.html) | pass | — |
| [inject.html](https://mark-liu.github.io/webguard/test/inject.html) | block | instruction-override (HTML comment) |
| [exfil.html](https://mark-liu.github.io/webguard/test/exfil.html) | block | exfil-instruction |
| [encoded.html](https://mark-liu.github.io/webguard/test/encoded.html) | block | instruction-override (base64) |
| [authority.html](https://mark-liu.github.io/webguard/test/authority.html) | block | authority-claim |

## Classifier

Two-stage cascade — fast pattern match, then heuristic scoring only when needed.

### Stage 1: Pattern Match

38 built-in patterns across 8 categories via hybrid Aho-Corasick (literals, single O(N) pass) + regex (structural patterns). Additional patterns can be loaded from external YAML files.

| Category | Patterns | Description |
|----------|----------|-------------|
| instruction-override | 7 | Attempts to override or reset prior instructions |
| prompt-marker | 6 | Fake system/instruction delimiters and chat markers |
| authority-claim | 6 | False claims of developer, admin, or elevated access |
| exfil-instruction | 5 | Data exfiltration via URLs or hidden elements |
| output-manipulation | 4 | Attempts to constrain or redirect model output |
| unicode-obfuscation | 4 | Zero-width chars, RTL overrides, Private Use Area |
| encoded-injection | 3 | Base64/eval/charcode obfuscated payloads |
| delimiter-injection | 3 | Fake prompt boundaries and role injections |

See [PATTERNS.md](PATTERNS.md) for the full pattern list with examples and regex definitions.

### Category Suppression

Suppress specific pattern categories per domain to eliminate false positives:

```yaml
domains:
  "*.linkedin.com":
    suppress: ["authority-claim"]
  "interactivebrokers.com":
    suppress: ["encoded-injection"]
```

Documentation URLs (`/docs/`, `/api/`, `/reference/`, `/sdk/`, etc.) automatically suppress `exfil-instruction` and `encoded-injection`.

### Stage 2: Heuristic Scoring

Only runs when Stage 1 finds non-critical matches. Factors:

- **Density**: matches per 1000 chars (>2.0 = 1.2x multiplier)
- **Clustering**: matches within 200 chars of each other (1.5x)
- **Proximity**: authority-claim + instruction-override nearby (1.5x)
- **Encoding penalty**: decoded content matches (1.3x)

### Sensitivity Levels

| Level | Threshold | Use Case |
|-------|-----------|----------|
| `low` | 2.0 | Documentation, trusted sources |
| `medium` | 1.0 | General browsing (default) |
| `high` | 0.5 | Untrusted sources |

## SSRF Prevention

All checks before any TCP connection:

- Private IP ranges (RFC 1918, loopback, link-local, carrier-grade NAT)
- Cloud metadata (AWS, GCP, Azure, Alibaba, Oracle, ECS)
- Octal IP detection (`0177.0.0.01`)
- URL-encoded hostname rejection
- `@` in URL authority rejection
- DNS pinning (resolve once, connect to resolved IP)
- **Re-validate on every redirect hop** (max 5) — prevents DNS rebinding and redirect-to-internal bypasses

## Configuration

`~/.config/webguard-mcp/config.yaml` — works with zero config (sensible defaults):

```yaml
sensitivity: medium
mode: block
max_body_size: 5242880
request_timeout: 15s
patterns_dir: ""

domains:
  "docs.python.org":
    sensitivity: low
    timeout: 30s
  "*.github.com":
    sensitivity: low
  "*.linkedin.com":
    suppress:
      - authority-claim

allowlist: []
blocklist: ["*.evil.com"]

audit:
  enabled: true
  path: ""  # default: ~/.local/share/webguard-mcp/audit.jsonl
```

## External Patterns

Add custom detection patterns by placing YAML files in the `patterns_dir` directory:

```yaml
# patterns.d/custom.yaml
patterns:
  - id: custom-001
    category: instruction-override
    severity: high
    type: literal
    value: "override all safety measures"
```

## Development

```bash
cargo build              # Build debug binary
cargo test               # Run all 77 tests
cargo build --release    # Build optimised binary
cargo clippy             # Lint
cargo fmt --check        # Format check
```

## Project Structure

```
webguard/
├── src/
│   ├── main.rs              # CLI entry, signal handling, MCP boot
│   ├── server.rs            # MCP tool handlers (fetch/status/report)
│   ├── config.rs            # YAML config, domain overrides
│   ├── audit.rs             # JSONL audit logger + reader
│   ├── fetch/
│   │   ├── ssrf.rs          # URL + IP validation, DNS pinning
│   │   ├── client.rs        # HTTP fetch, redirect recheck, retry
│   │   └── extract.rs       # HTML → markdown
│   └── classify/
│       ├── engine.rs        # Two-stage orchestrator
│       ├── preprocess.rs    # 8-step content preprocessing
│       ├── stage1.rs        # Aho-Corasick + regex scanner
│       ├── stage2.rs        # Heuristic scoring
│       ├── patterns.rs      # 38 built-in patterns
│       ├── external.rs      # External pattern YAML loader
│       ├── encoding.rs      # Base64/URL/hex/ROT13 decode
│       └── result.rs        # Result types
├── docs/test/               # GitHub Pages test pages
├── testdata/                # Test fixtures (14 JSON files)
└── patterns.d/              # External pattern directory
```

## Related Projects

- **[webguard-mcp](https://github.com/mark-liu/webguard-mcp)** — the original Go implementation (superseded by this repo)
- **[mcpguard](https://github.com/mark-liu/mcpguard)** — MCP stdio proxy that scans tool results from any MCP server (Discord, Telegram, etc.) for prompt injection
- **[snap](https://github.com/mark-liu/snap)** — MCP stdio compression proxy for Playwright snapshots

## License

MIT
