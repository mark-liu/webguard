# Changelog

## Unreleased

### Fixed - "New instructions:" docs labels no longer block

io-006 matched the bare label `new instructions:`, so a page saying
`**New instructions:** run tests` was blocked outright (one high match
crosses the default threshold). It now needs an override cue after the
colon (`you`, `your`, `ignore`, `disregard`, `forget`, `from now on`,
`act as`, `pretend`, `reveal`, `override`), and also catches the singular
`new instruction:`.

### Fixed - deeply nested pages no longer crash webguard

A page with about 5000 nested tags overflowed the stack in the HTML to
markdown converter, which aborts the whole process rather than failing the
fetch. Elements deeper than 512 levels (Chromium's parser cap) are now
unwrapped before conversion: their text stays in place and is still scanned,
only the excess tags are dropped.

## 0.5.5 - 2026-10-10

### Added - audit tag for synthetic traffic

`WEBGUARD_AUDIT_TAG` writes a `tag` field on every audit row, and
`webguard_report` excludes tagged rows from its counts and says how many it
skipped, so replays and canaries no longer skew block rates. Same contract as
mcpguard's `MCPGUARD_AUDIT_TAG`. Old rows parse unchanged.

## 0.5.4 - 2026-10-10

### Fixed - markup that splits a phrase no longer hides it

Inline HTML elements (`ig<b>no</b>re`) now join the words on either side, as
a browser renders them; only block elements and `<br>` separate text. A copy
of the text without markdown inline markup (`**`, `_`, `` ` ``, `~`, `\`,
brackets, link destinations, with a link's title joined to its text) is
scanned as an extra view, so `ignore \[previous\] instructions` and
`[ignore](x "previous instructions")` match. The view comes from a CommonMark
parser, so image alt text counts and code stays literal. In prose a bracket
is dropped only inside a word (`i]g[n]o[r]e`) or as a pair hugging a word
(`[previous]`), so a regex such as `ignore[ ]previous` is not rewritten into
the phrase. Inline elements now
include `label`, `button`, `ruby` and custom elements; `img` contributes its
alt text. Invisible format characters (U+200E/F, U+2060-2064, bidi controls,
variation selectors, Hangul fillers and similar) are stripped before matching
in every view, including raw attributes, comments and decoded blobs, without
counting as zero-width obfuscation; comments, decoded blobs and comments
inside decoded blobs also get the markdown-free view, and link titles lose their brackets too. Known gaps: a
markdown split inside a raw HTML attribute (`title="ig[no](x)re ..."`) is not
joined, since the parser reads an HTML block as opaque, and bracketed token
lists such as `[ignore] [previous] [instructions]` now block, the cost of
catching `ignore [previous] instructions`. One hit seen in several views counts once
even when the views differ only in markup. Marker fixtures are back to
marker-only content and test detection.

## 0.5.3 - 2026-10-10

### Fixed - panic on length-changing lowercase

Literal matching sliced the original text with offsets from its lowercased
copy, so a page with `İ` (U+0130) before a matched phrase panicked the scan.
Offsets now map back through the lowercase per byte.

### Changed - marker families never block alone

`prompt-marker` and `delimiter-injection` hits (pm-*, di-*) no longer produce a
block by themselves: a page whose only matches are in those two families
passes, with the matches still logged. A block needs at least one match from
another family, then follows the existing critical/scoring path. This stops
false blocks on LLM source code, model cards and API docs that quote chat
templates. pm-001 (`<|im_start|>system`) drops from critical to high.

### Added - `cgnat_host_suffixes`

New config list of hostname suffixes (dot-boundary match) that may resolve into
`100.64.0.0/10`, for overlay networks such as `example-tailnet.ts.net`. It
lifts that one range only: loopback, link-local, RFC 1918, unique-local IPv6
and cloud metadata IPs (including `100.100.100.200`) stay blocked, and IP
literals in the URL never qualify. The check runs on the IP actually connected
to, on the first request and every redirect hop. Default empty.

### Fixed - Unicode folding before matching

NBSP and other Unicode space separators now fold to ASCII space, soft hyphens
are removed, and NFKC folds fullwidth letters, so `ignore&nbsp;previous&nbsp;instructions`,
`ig\u00ADnore previous instructions` and fullwidth text no longer slip past
literal patterns. Applies to the extracted text, the raw body, HTML comments
and decoded blobs. Cyrillic confusables are not handled.

## 0.5.2 - 2026-10-10

### Fixed - scan what the model receives

Non-raw fetches scanned the full raw body, including inline `<script>` text
that `extract_clean` removes, so `String.fromCharCode(` in a search-results
page blocked the fetch. Non-raw fetches now run two scans and block if either
blocks: the extracted document the model receives (before `offset`/`max_chars`
slicing, so a range read cannot dodge it), and the raw body with script,
style, noscript, svg, iframe elements and HTML comments removed. The second
scan catches attacks that markdown conversion splits or hides (inline `<b>`,
links, `<br>`, tables, lists, entity-encoded markers, a stray `<` swallowing a
base64 blob). `raw=true` still scans the raw body unchanged. HTML comments are
not delivered to the model, so they are scanned only with `raw=true`.

### Fixed - element removal follows the HTML parser

Script, style, noscript, svg, iframe and comment removal now detaches nodes
from one html5ever parse instead of matching a regex or string-replacing
serialised elements. The regex disagreed with the tokenizer on markers inside
attribute values, `</script/>`, abrupt comments (`<!-->`, `--!>`), svg
breakout and RCDATA, and could drop delivered text from the second scan;
`<SCRIPT>`, `<noscript>` and unquoted-attribute `<svg>` content could reach
the model. Extraction of a 5.6 MB page drops from about 30 s to under 2 s.

### Changed - enc-003 accepts hex char codes

`String.fromCharCode(0x69, 0x67, ...)` now matches alongside decimal runs.

### Fixed - one occurrence scored once

Stage 1 deduped by offset, but the stripped and raw texts have different
offsets, so one phrase scored twice. Matches now dedupe across texts by
(pattern, matched text); a phrase repeated within a document still counts
per occurrence.

### Fixed - doc auto-suppression narrowed

`pypi.org` and `readthedocs.io`/`.org` host publisher-controlled content and
are no longer treated as doc sites, so `ei-*` and `enc-*` matches there are
no longer suppressed. Doc path checks match whole segments, not substrings
(`/project/api-foo` is not `/api`).

## 0.5.1 - 2026-10-10

### Fixed - `@` in a URL path no longer rejected

The SSRF check refused any URL containing `@`, so `https://medium.com/@user/post`
failed with "@ in authority". The check now bounds the authority at `/ ? #` or
backslash before looking for `@`, and treats a password-only userinfo
(`https://:pw@host`) as userinfo.

## 0.5.0 - 2026-10-03

### Changed - non-HTML bodies returned verbatim

`text/*` (except HTML), JSON, TOML, YAML, XML and JS responses skip the
HTML-to-markdown pass, so raw files match `curl` byte for byte. The injection
scan is unchanged.

### Added - `offset` range reads, default cap 50000

`webguard_fetch` takes `offset` (chars). A truncated window ends with a trailer
naming the total length and the next offset. `max_chars` now counts chars, not
bytes, and the default drops from 90000 to 50000 to fit under the client's
tool-result wall. The whole body is scanned once per call, so every window of a
document gets the same verdict.

### Added - audit row size fields and `low-content` verdict

Audit rows gain `content_type`, `bytes`, `extracted_chars`, `truncated` and
`cap` (zero values omitted; `truncated` means the returned window was cut by
`cap`). `content_type` is reduced to the base MIME (lowercase, no parameters,
`[a-z0-9.+-/]` only, else `invalid`) before it is written. A 200 HTML response
extracting to under 50 chars logs and reports verdict `low-content` instead of
`pass`; 204 and other non-200 statuses are exempt. `webguard_report` shows the
"Low extracted content" count and the truncation rate over non-blocked rows
that carry size data, zero-char responses included.

## 0.4.5 - 2026-08-22

### Changed - `max_chars` defaults to 90000

`webguard_fetch` with no `max_chars` returned the whole page. 99 of 241 calls in
30d on one host exceeded the client's 25k-token tool-result cap, so the page was
spilled to a file and the model saw none of it. The server now caps at 90000
chars (~22k tokens) unless the caller sets `max_chars`; `0` still means
unlimited, and `WEBGUARD_DEFAULT_MAX_CHARS` overrides the default. Truncated
output ends with `[webguard: truncated to N of M chars; pass max_chars: 0 for
the full page]` so the caller can re-fetch deliberately.

## 0.4.1 — 2026-05-24

### Removed — pattern ei-002 (`exfiltrate` literal)

The bare literal `exfiltrate` was matching legitimate content: security marketing
copy (promptarmor.com, llm-guard, vigil-llm READMEs), webguard's own docs, and
any blog post discussing exfiltration. A single occurrence of the word inside
otherwise-benign prose triggered High-severity scoring and pushed totals over the
medium-sensitivity threshold (4.5), producing a block.

True exfiltration *instructions* are still covered by ei-001/003/004/005 — every
remaining pattern in the category requires either a target verb (send/fetch/
load/visit/open/navigate) or a destination URL. The accepted recall trade-off is
prose that uses the word "exfiltrate" without an accompanying URL or imperative
verb; that case is marked `explicit exfiltrate` in `known_gaps` (see
`src/classify/engine.rs`).

Pattern count: 38 → 37. No score-threshold change.

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

Removed from the mixed doc-host list: `pypi.org`, `readthedocs.io`,
`readthedocs.org`, `crates.io`, `hex.pm`, `registry.terraform.io` (package
names like `api` or `docs` collide with path-segment checks). The pure doc
hosts (`docs.rs`, `pkg.go.dev`, `hexdocs.pm`, `javadoc.io`, `rubydoc.info`,
and the rest of the pure list) still auto-suppress non-critical `ei-004`,
`ei-005` and `enc-*` matches on any non-root path.
