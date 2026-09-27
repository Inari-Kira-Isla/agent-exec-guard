# agent-exec-guard

Two small, dependency-free tools for a pattern that comes up anywhere you run
an LLM CLI agent over untrusted text and don't want to just believe what it
gives back:

1. **`harden-codex-exec.sh`** — run `codex exec` (OpenAI's Codex CLI) with
   its network/tool-access surface actually locked down, and fail loud if
   anything outside an expected event-type allowlist shows up in its
   structured output.
2. **`verify_lib.py`** — a generic Python library that checks LLM-generated
   text against a source-of-truth fact list you built yourself, catching
   fabricated entities, unlisted URLs, wrong numbers, and leaked secrets.

Both came out of hardening a real automation pipeline (a weekly digest
generator that runs an LLM over scraped data on a schedule, unattended). In
the course of building it we found and fixed three real bugs — not
hypothetical ones — in earlier, naive versions of this exact pattern. That's
the reason this exists as its own project instead of staying buried in one
pipeline's shell script.

## The three bugs

### 1. `-s read-only` doesn't mean "can't reach the network"

Codex's `exec -s read-only` sandbox flag blocks filesystem *writes*. It does
**not** disable MCP servers, or built-in features like `apps`/connectors,
`browser_use`, `computer_use`, `plugins`, `multi_agent`, `image_generation`,
or `web_search`, from reaching the network or executing code outside the
sandbox. A prompt that gets the model to call a configured MCP tool can
exfiltrate data or hit the network even in "read-only" mode — the sandbox
flag was never designed to cover that surface.

**Fix:** before running, dynamically enumerate every configured MCP server
with `codex mcp list --json` (never assume the config file on disk is the
full picture — plugin-injected servers exist too) and explicitly disable
each one by name: `-c mcp_servers.<name>.enabled=false`. Add
`--disable apps browser_use computer_use plugins multi_agent
image_generation` and `-c tools.web_search=false` on top. Then verify —
don't just configure and hope — via the structured `--json` output that
*only* expected event types occurred.

### 2. Grepping the log for suspicious text produces false positives *and* misses real bypasses

An earlier version checked the agent's log by grepping unstructured text for
suspicious keywords. Legitimate output regularly contains literal words like
`false`, or benign status strings, that trigger false positives on a clean
run — and a real bypass could, in principle, hide inside otherwise
normal-looking text, producing a false negative in the other direction.

**Fix:** require Codex's structured `--json` event stream and allowlist only
specific `item.type` values (`agent_message`, `command_execution`, `error`
by default) — never regex/grep raw log text for a security decision. Also
require at least one real `agent_message` event: an empty or truncated log
must not pass just because it also contains zero violations.

### 3. The anti-fabrication checker had real, demonstrated bypasses

Adversarial testing against an earlier verifier found several distinct
bypass classes:

- A fabricated entity in a **non-bold** format (`fakeorg/fakerepo（★50000）`
  with no markdown bold) or mentioned **mid-sentence with no URL attached**
  sometimes passed a checker that only looked at bolded or URL-shaped
  tokens.
- A **protocol-relative URL** (`//evil.example.com/...`) passed a naive
  `https://`-prefix-only check.
- The secret scanner had a **false positive**: it matched the literal text
  `sk-hynix` inside a legitimate real-world URL
  (`.../sk-hynix-reportedly-expands-hbm-output`).
- The same scanner had a **false negative**: it only covered OpenAI-style
  `sk-...` keys and missed Anthropic-format keys (`sk-ant-...`), which share
  a prefix but are a structurally different credential.
- **A follow-up review round found a fifth bypass and a bug in the first
  fix's own reasoning**, both worth calling out explicitly since the first
  version of this README got them wrong:
  - A **Unicode homoglyph bypass**: `fakеorg/repo` — using Cyrillic
    'е' (U+0435) instead of Latin 'e' — matched none of the entity checks,
    because Python's `\b` treats every Unicode letter as a "word"
    character, so there was no boundary between the Cyrillic letter and the
    following ASCII letters for an ASCII-only, `\b`-anchored regex to latch
    onto. The token simply never matched anything, and slipped through
    unflagged.
  - The original fix for the `sk-hynix` false positive reasoned "real key
    bodies never contain hyphens" and applied that as a blanket rule to
    all `sk-...` keys. That rule is false: OpenAI's own `sk-proj-...`
    project key format legitimately contains hyphens and underscores in
    the body. The blanket rule would have false-negatived on a real
    `sk-proj-` key while claiming to be the fix for a false positive.

**Fixes**, one per bypass:

- Build the allowlist from source-of-truth JSON **before** the agent runs,
  never parse it back out of the agent's own output — an agent with any
  write access could otherwise doctor the allowlist itself.
- Re-verify the source JSON's sha256 hasn't changed after the run.
- Detect entity mentions **whether or not** they're bold or attached to a
  URL — a fabricated name that just skips the markup still needs to fail.
  Entity-shaped tokens are matched on a boundary character class —
  whitespace, brackets/quotes, fullwidth CJK punctuation, standard ASCII
  punctuation (`, . ; : ! ?`), and the numeric marker symbols (`★ $ #`) —
  rather than `\b`, for this same reason (see below). Standard ASCII
  punctuation had to be added explicitly here after review found a
  regression: without it, a trailing comma got pulled into the match
  (`"openai/whisper,"` misread as a different, fabricated entity) and a
  marker glued directly onto a name with no space
  (`"openai/whisper★71234"`) pulled the `★` into the token and tripped the
  non-ASCII/homoglyph check on a real entity.
- Catch scheme-less and protocol-relative URLs/domains, not just
  `https://`-prefixed ones.
- Distinguish real keys from look-alike URL text using a **structural
  marker** per provider, not a punctuation heuristic: OpenAI legacy `sk-`
  keys are matched as a long contiguous alnum run (no hyphen) with a
  negative lookahead against `proj-`/`svcacct-`/`None-`; OpenAI
  `sk-proj-`, `sk-svcacct-` (service account keys), and `sk-None-` (seen
  when an org id is unset client-side) keys are each matched separately,
  requiring their own literal marker, with hyphens/underscores allowed in
  the body; `sk-ant-` (Anthropic) is its own explicit pattern.
  `sk-hynix-reportedly-...` matches none of these, because it contains
  neither 20+ contiguous alnum chars after `sk-` nor any of the literal
  markers. (The `sk-svcacct-`/`sk-None-` formats and the ASCII-punctuation
  entity-boundary fix below were both found in a second adversarial review
  round, after the first version of this pattern list shipped — see
  `verify_lib.py`'s SECRET_PATTERNS comment for the standing caveat that
  this is not a claim of zero false positives/negatives against every key
  format that exists.)
- Verify claims against **both** the entity *and* its numeric fact — a real
  repo name attached to a fabricated star count is still a fabrication; the
  claimed number must match the source record's real value within
  tolerance, not just "does this token exist somewhere in the allowlist."
- Reject/flag any entity-shaped mention that contains a **non-ASCII
  character** outright, rather than attempting Unicode normalization.
  NFKC normalization was considered and deliberately rejected for this:
  NFKC only folds *compatibility* variants of a character (full-width
  forms, ligatures, etc.), not cross-script look-alikes — Cyrillic 'е'
  (U+0435) and Latin 'e' (U+0065) are canonically distinct letters in
  different scripts, and NFKC leaves them exactly as they are. Actually
  solving homoglyph spoofing in general needs a confusables-skeleton
  algorithm (Unicode TR39), which is a bigger dependency than this library
  wants to carry. Since trusted fact `id`s are documented to be plain
  ASCII, flatly rejecting non-ASCII characters inside an entity-shaped
  token is both simpler and can't be evaded by picking a different script.

Every one of these is a real `pytest` test in `tests/test_verify_lib.py`
(`test_non_bold_fake_entity_with_star_count_is_caught`,
`test_protocol_relative_url_not_in_allowlist_is_caught`,
`test_sk_hynix_real_url_does_not_false_positive`,
`test_anthropic_key_format_is_detected`,
`test_openai_sk_proj_key_with_hyphens_and_underscores_is_detected`,
`test_cyrillic_homoglyph_entity_is_caught`,
`test_star_count_mismatch_is_caught`,
`test_sha256_tamper_after_run_is_detected`, plus supporting cases — 29
tests total). Each bypass also has a runnable, **committed** side-by-side
comparison in `examples/naive_vs_fixed_demo.py`: a deliberately naive
stand-in implementation (bold-only entity regex, `https://`-prefix-only URL
check, hyphen-tolerant secret regex, OpenAI-only key pattern, the old
blanket "no hyphens" rule, an ASCII-`\b`-anchored entity regex) reproducing
each exact bypass, immediately followed by `verify_lib` catching the same
case. Run it with `python3 examples/naive_vs_fixed_demo.py`. This repo
intentionally keeps a single clean commit rather than a bug-fix-per-commit
history, so this script — not `git log` — is the canonical place to see the
before/after.

## Install

No dependencies beyond the Python 3.9+ standard library for `verify_lib.py`,
and `bash` + `python3` for `harden-codex-exec.sh`. For running the test
suite:

```bash
pip install -r requirements-dev.txt
pytest tests/
```

Nothing to build or package — just copy `verify_lib.py` and/or
`harden-codex-exec.sh` into your project, or add this repo as a git
submodule/subtree.

## Usage: `harden-codex-exec.sh`

```bash
chmod +x harden-codex-exec.sh

# Real run — everything after the wrapper's own flags is passed straight
# through to `codex exec`.
./harden-codex-exec.sh -m gpt-5.5 "Summarize this untrusted text: ..."

# See exactly what would run (which MCP servers get disabled, full codex
# command line) without spending any API quota:
./harden-codex-exec.sh --dry-run -m gpt-5.5 "some prompt"

# Prompt piped on stdin, same as plain `codex exec -`:
cat untrusted_input.txt | ./harden-codex-exec.sh -m gpt-5.5 -
```

Exit codes: `0` = clean run, event stream inside the allowlist, at least one
real `agent_message` observed. `1` = BLOCKED (MCP enumeration failed, a
disallowed event type showed up, codex itself exited non-zero, or the log
was empty/truncated). `2` = usage error.

Override the allowlist with `--allowed-types` or the
`AGENT_EXEC_GUARD_ALLOWED_TYPES` env var if your use case legitimately needs
additional item types — but understand each type you add is something you're
now trusting to be safe.

## Usage: `verify_lib.py`

```python
from verify_lib import verify

trusted_facts = [
    {
        "id": "openai/whisper",                       # required, unique id
        "url": "https://github.com/openai/whisper",     # optional canonical URL
        "urls": [],                                       # optional extra allowed URLs
        "metrics": {"stars": 71234},                     # optional numeric facts
    },
]

llm_output = "**openai/whisper**（★71234） — speech recognition, https://github.com/openai/whisper"

result = verify(llm_output, trusted_facts, metric_key="stars")
if not result.ok:
    for err in result.errors:
        print("BLOCKED:", err)
    raise SystemExit(1)
```

`trusted_facts` is intentionally generic — `id` can be a repo slug, a SKU, a
case number, a company name; whatever your LLM is being asked to summarize
or cite. `metrics` are checked as a dict of arbitrary named numeric facts, so
the same library works for star counts, prices, headcounts, or anything
else with a "the model claimed N, does N match the source" shape.

The individual checks are separately importable for composing your own
pipeline: `hash_file`, `verify_integrity`, `extract_urls`, `check_urls`,
`extract_entity_mentions`, `check_entities_and_metrics`, `scan_secrets`.

To also verify your source-of-truth file wasn't tampered with during the
LLM run:

```python
from verify_lib import hash_file, verify

before = hash_file("facts.json")   # capture BEFORE running the LLM
# ... run your LLM ...
result = verify(llm_output, trusted_facts,
                 source_file_path="facts.json",
                 source_sha256_before=before,
                 metric_key="stars")
```

See `examples/verify_example.py` for a runnable end-to-end example, and
`examples/naive_vs_fixed_demo.py` for the naive-vs-fixed bypass comparisons.

## Known limitations

`verify_lib.py`'s checks are pattern-based, not a full parser, and are
deliberately conservative about what they promise. Known gaps, left
unfixed because a real fix needs either a different architecture or a
domain-specific extractor rather than a regex tweak:

- **A claimed number must appear on the same line as the entity mention,
  immediately after it, with an explicit marker (`★`/`$`/`#`).** A number
  placed *before* the entity name, on the following line, or with no marker
  at all, is not checked against the source — this is a real gap, not just
  a formatting nuance. If your output format doesn't naturally put
  `**name**（★N）` on one line, pass your own `entity_pattern` and drive
  `check_entities_and_metrics` per-record yourself, or post-process your
  LLM's output into that shape before verifying it.
- **Bare-domain URLs with no path** (e.g. a byline like `— reuters.com`
  with nothing after it) are intentionally NOT treated as link claims, to
  avoid flagging ordinary attribution text as a fabricated link. This means
  a bare-domain reference that *should* have been checked (e.g. a claim
  that literally is just a domain name) is not.
- **`mailto:` links and domains under TLDs outside the hardcoded allowlist**
  (`com org net io ai dev co app blog news edu gov me so xyz`) are not
  recognized as URL-shaped tokens at all, so they neither get flagged as
  untraceable NOR benefit from allowlist matching. If your domain uses an
  uncommon TLD, extend `BARE_DOMAIN_RE` or rely on requiring full
  `https://` URLs in your own prompt design.
- **A secret split across two lines** (e.g. a key value word-wrapped by the
  LLM) will not match any of the single-line regexes in `SECRET_PATTERNS`.
  If you expect this failure mode, normalize/dehyphenate line-wrapped text
  before calling `scan_secrets`.
- **Numeric claim parsing is pattern-based**, not a full grammar. It was
  hardened against a bare year in prose being misread as a metric value
  (the marker is now mandatory) and against malformed comma-grouping being
  silently reassembled into a different number (`\d{1,3}(?:,\d{3})*`
  thousands-grouping is enforced) — see `test_year_in_prose_is_not_misread`
  and `test_malformed_comma_grouping_not_silently_reassembled`. But it does
  not understand, for example, negative numbers, scientific notation, or
  numbers written out as words ("seventy-one thousand").
- **Homoglyph rejection is ASCII-vs-non-ASCII, not a confusables-skeleton
  algorithm.** It reliably rejects any entity mention using non-Latin
  script letters (Cyrillic, Greek, fullwidth Latin, etc.), which covers the
  demonstrated bypass. It does NOT detect a homoglyph attack built entirely
  from *other* ASCII characters (e.g. using `rn` to visually approximate
  `m`), since those characters are legitimately ASCII. Closing that gap
  fully needs Unicode TR39 confusables data, which this library
  intentionally does not depend on.

## What was actually verified for real vs. what wasn't

- `verify_lib.py`: all 29 pytest cases run and pass on this machine
  (`pytest tests/`). Every documented bug — including the two found in the
  follow-up review rounds (Unicode homoglyph, the `sk-proj-`/`sk-svcacct-`/
  `sk-None-` false negatives, and the ASCII-punctuation entity-boundary
  regression) — has a dedicated test, plus a
  companion runnable comparison in `examples/naive_vs_fixed_demo.py`
  showing a naive implementation get bypassed on the exact same input.
- `harden-codex-exec.sh`: run for real against a live `codex exec` call on
  this machine (model `gpt-5.5`, minimal prompt, real API usage — kept
  deliberately tiny to limit cost) and confirmed: MCP servers were correctly
  enumerated and disabled, the run completed, the structured-event allowlist
  check passed, and exit code was `0`.
- The **fail-closed path** (a disallowed `item.type` like `mcp_tool_call`
  appearing in the log, an empty/truncated log, and a server entry with a
  missing `enabled` field) was verified by substituting a fake `codex`
  binary (via the `CODEX_BIN` env var) that emits a synthetic JSONL event
  stream / MCP list containing each condition, and confirming the real
  wrapper script — not a copy of its logic — correctly exits `1` (or
  correctly disables the ambiguous server) in every case. We did not
  attempt to make a real Codex run actually call a live MCP tool against
  instructions to prove a real bypass exists in an unpatched wrapper; that
  would require reintroducing the vulnerability found in bug #1 and might
  cost real API quota performing a real network call, so we verified the
  detection logic against a controlled fake instead.
- **`codex mcp list --json` schema check**: run for real on this machine
  against codex-cli 0.153.4. Every entry currently returned an explicit
  boolean `enabled` field — there was no server missing it to observe on
  this install. Since we can't guarantee that holds on every past/future
  codex-cli version, the enumeration loop treats a missing/null `enabled`
  field the same as `enabled: true` (default to disabling it) rather than
  silently skipping it, and this default-disable behavior with a
  missing-field entry was verified for real via the fake-binary substitution
  above. More importantly: **the MCP-disable step is defense in depth, not
  the actual guarantee.** The real fail-closed backstop is the structured
  `--json` event-type allowlist check — even if enumeration missed a
  server entirely, any `mcp_tool_call` event it produced still gets caught
  there, which is the condition that was actually verified end-to-end.
- One real bug was found *during this verification*: on macOS's shipped
  `/bin/bash` (3.2.57, pre-4.4), `"${arr[@]}"` on a **genuinely empty**
  array raises `unbound variable` under `set -u`, which happens exactly
  when there are zero enabled MCP servers to disable. Fixed with the
  portable `${arr[@]+"${arr[@]}"}` expansion. This is a good example of why
  "test it for real" mattered here — it would not have been caught by
  reading the script.

## License

MIT — see `LICENSE`.
