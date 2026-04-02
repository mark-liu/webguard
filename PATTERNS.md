# Pattern Reference

Full list of 38 detection patterns used by the WebGuard classifier.

## Pattern Format

Each pattern has:
- **ID**: category prefix + number (e.g. `io-001`)
- **Category**: attack type
- **Severity**: critical, high, or medium
- **Type**: `literal` (Aho-Corasick, case-insensitive) or `regex`

Critical severity triggers immediate block at Stage 1 regardless of threshold.

## instruction-override (7 patterns)

Attempts to override, reset, or replace prior instructions.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| io-001 | critical | literal | `ignore previous instructions` |
| io-002 | critical | literal | `ignore all previous` |
| io-003 | critical | literal | `disregard previous instructions` |
| io-004 | high | literal | `forget your instructions` |
| io-005 | high | literal | `from now on you will` |
| io-006 | high | literal | `new instructions:` |
| io-007 | critical | regex | `(?i)ignore\s+(any\|all\|every)\s+(prior\|previous\|earlier)\s+(instructions?\|prompts?\|rules?)` |

## prompt-marker (6 patterns)

Fake system/instruction delimiters and chat template markers.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| pm-001 | critical | literal | `<\|im_start\|>system` |
| pm-002 | high | literal | `<\|im_start\|>` |
| pm-003 | high | literal | `[system]:` |
| pm-004 | high | literal | `[inst]` |
| pm-005 | critical | literal | `<<sys>>` |
| pm-006 | high | regex | `(?i)\[/?INST\]` |

## authority-claim (6 patterns)

False claims of developer, admin, or elevated access.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| ac-001 | critical | literal | `i am your developer` |
| ac-002 | high | literal | `i am the system administrator` |
| ac-003 | high | literal | `dan mode` |
| ac-004 | high | literal | `admin override` |
| ac-005 | medium | literal | `you are now in` |
| ac-006 | critical | regex | `(?i)(I\s+am\|this\s+is)\s+(your\|the)\s+(developer\|creator\|admin\|administrator\|owner)` |

## exfil-instruction (5 patterns)

Data exfiltration via URLs, hidden elements, or direct commands.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| ei-001 | critical | literal | `send all data to` |
| ei-002 | high | literal | `exfiltrate` |
| ei-003 | critical | regex | `(?i)send\s+(all\|the\|this\|your)\s+(the\s+)?(data\|information\|context\|conversation)\s+(and\s+\w+\s+)?to\s+(https?://\|//\|[domain])` |
| ei-004 | high | regex | `(?i)(fetch\|load\|visit\|open\|navigate)\s+(https?://\|//)[^\s]+` |
| ei-005 | high | regex | `!\[(track\|pixel\|1x1\|beacon\|exfil)\w*\]\(https?://...\)` |

## output-manipulation (4 patterns)

Attempts to constrain or redirect model output.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| om-001 | medium | literal | `respond only with` |
| om-002 | medium | literal | `do not mention` |
| om-003 | high | regex | `(?i)never\s+(mention\|reveal\|disclose\|discuss)\s+(that\|this\|the\|your)` |
| om-004 | medium | regex | `(?i)(always\|must\|should)\s+respond\s+(with\|by\|using)\s+` |

## unicode-obfuscation (4 patterns)

Invisible or direction-changing Unicode characters used to hide content.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| uo-001 | high | regex | 3+ consecutive zero-width chars (U+200B/200C/200D/FEFF) |
| uo-002 | medium | regex | 2+ consecutive bidi overrides (U+202A-202E, U+2066-2069) |
| uo-003 | medium | regex | 2+ consecutive Private Use Area chars (U+E000-F8FF) |
| uo-004 | high | regex | Tag characters (U+E0001-E007F) |

## encoded-injection (3 patterns)

Payloads obfuscated via encoding functions.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| enc-001 | high | regex | `(?i)eval\s*\(\s*atob\s*\(` |
| enc-002 | medium | regex | `(?i)base64[_-]?decode` |
| enc-003 | medium | regex | `(?i)String\.fromCharCode\s*\(` |

## delimiter-injection (3 patterns)

Fake prompt boundaries and role injections.

| ID | Severity | Type | Pattern |
|----|----------|------|---------|
| di-001 | high | literal | `---end system prompt---` |
| di-002 | high | regex | `(?i)-{3,}\s*(END\|BEGIN)\s+(SYSTEM\|USER\|ASSISTANT)\s+(PROMPT\|MESSAGE\|INSTRUCTIONS?)\s*-{3,}` |
| di-003 | high | regex | `\{\s*"role"\s*:\s*"(system\|assistant)"\s*` |

## Severity Weights

| Severity | Weight | Behaviour |
|----------|--------|-----------|
| critical | 2.0 | Immediate block at Stage 1 |
| high | 1.5 | Scored in Stage 2 |
| medium | 1.0 | Scored in Stage 2 |
