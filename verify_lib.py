#!/usr/bin/env python3
"""verify_lib — generic anti-fabrication / anti-leak verifier for LLM output.

Use case: you ran an LLM (any model, any CLI) over some untrusted input and
got back generated text that makes factual claims (entity names, URLs,
numbers). Before you trust that text — publish it, commit it, act on it —
run it through this library against a "trusted facts" record you built
*yourself*, from a source you control, *before* the LLM ever ran.

Design principles (each one exists because a naive version of it produced a
real, demonstrated bypass — see README for the incident writeups):

1. Build the allowlist from source-of-truth data BEFORE the LLM runs, never
   parse it back out of the LLM's own output. An agent with any write access
   could otherwise doctor the "allowed" list itself.
2. Re-hash the source file after the run. If it changed, nothing downstream
   can be trusted — the agent (or something else) touched ground truth.
3. Catch every plausible URL shape, not just `https://` — scheme-less bare
   domains with a path, and protocol-relative `//host/path` links, are still
   links, and both have been used to sneak an unlisted destination past a
   `https://`-prefix-only checker.
4. Detect fabricated entities whether or not the LLM bothered to markdown-bold
   them or attach a URL. A checker that only looks at `**bold**` tokens or
   URL-shaped tokens can be bypassed by simply not bolding the fake claim.
5. Verify claimed numbers against the source record's actual value, not just
   "does this token exist somewhere in the allowlist" — a real entity name
   attached to a fabricated number is still a fabrication.
6. Secret-pattern matching needs strict per-provider shape, matched on real
   structural markers rather than a punctuation guess. Distinguishing
   real keys from URLs by "no hyphens allowed" false-negatives on OpenAI's
   own `sk-proj-...` format (which legitimately contains hyphens/
   underscores) — the correct discriminator is the literal `proj-` marker,
   not the presence of punctuation. Too narrow (only checking OpenAI's
   `sk-` prefix) false-negatives on Anthropic's `sk-ant-` keys, which start
   with the same two letters but are a different credential.
7. A non-ASCII character inside what looks like an entity-name token (e.g.
   Cyrillic 'е' standing in for Latin 'e' in "fakеorg/repo") is flagged
   outright rather than relying on Unicode normalization — NFKC does not
   fold cross-script look-alikes, so it would not catch this.

Schema for a trusted fact record (list[dict], keep it as generic or as
domain-specific as you like — only `id` is required):

    {
        "id": "openai/whisper",        # required, unique identifier string
        "url": "https://github.com/...",   # optional canonical URL
        "urls": ["https://mirror.example/..."],  # optional extra allowed URLs
        "metrics": {"stars": 71234, "forks": 8000}  # optional numeric facts
    }

Nothing here is GitHub-specific: `id` can be a SKU, a company name, a case
number — anything an LLM might mention and attach a number or link to.
`metrics` values are checked against whatever the LLM's output claims for
that same key.
"""
from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

# --------------------------------------------------------------------------
# Data types
# --------------------------------------------------------------------------


@dataclass
class VerifyResult:
    ok: bool
    errors: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


# --------------------------------------------------------------------------
# 1. Integrity: sha256 of the trusted-facts source file, before vs after
# --------------------------------------------------------------------------


def hash_file(path: str) -> str:
    """Return the sha256 hex digest of a file's current contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_integrity(path: str, expected_sha256: str) -> tuple[bool, str]:
    """Re-hash `path` and compare against a hash captured earlier (before the
    LLM ran). Returns (matches, actual_hash). Call this *after* the LLM run,
    using a hash you captured with hash_file() *before* the run — never trust
    a hash the LLM itself reports.
    """
    actual = hash_file(path)
    return (actual == expected_sha256, actual)


# --------------------------------------------------------------------------
# 2. URL extraction — full, scheme-less, and protocol-relative forms
# --------------------------------------------------------------------------

_STOP_CHARS = r'\s<>\[\]()"\'`，。！？；：、「」『』'
_FULLWIDTH_TRAIL = "，。！？；：、」』】》〉…—～·､｡｣"
_ASCII_TRAIL = ".,;:)"

FULL_URL_RE = re.compile(r"https?://[^" + _STOP_CHARS + r"]+")
ANGLE_URL_RE = re.compile(r"<(https?://[^>\s]+)>")

# Scheme-less bare domain that is followed by a path — a domain mention on
# its own (e.g. a byline "— reuters.com") is not treated as a link claim.
BARE_DOMAIN_RE = re.compile(
    r"(?<![\w./:])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|org|net|io|ai|dev|co|app|blog|news|edu|gov|me|so|xyz)"
    r"/[^" + _STOP_CHARS + r"]+"
)

# Protocol-relative link: //host/path. The lookbehind excludes the "//" that
# follows "https:" in a normal URL, so this never double-counts real URLs.
PROTOCOL_RELATIVE_RE = re.compile(r"(?<![:\w])//[^" + _STOP_CHARS + r"]{2,}")


def _strip_trailing_punct(u: str) -> str:
    return u.rstrip(_FULLWIDTH_TRAIL + _ASCII_TRAIL)


def normalize_url(u: str) -> str:
    """Strip scheme, leading //, www., and trailing slash so that
    'https://www.example.com/x/', '//example.com/x' and 'example.com/x'
    all normalize to the same comparable string."""
    u = _strip_trailing_punct(u)
    u = re.sub(r"^https?://", "", u)
    u = u.lstrip("/")
    u = re.sub(r"^www\.", "", u)
    return u.rstrip("/")


def extract_urls(text: str) -> set[str]:
    """Return every URL-shaped token in text: full https:// URLs (including
    ones wrapped in <angle brackets>), scheme-less bare domains with a path,
    and protocol-relative //host/path links. Each returned string is the
    raw matched token (not yet normalized)."""
    found: set[str] = set()
    for m in ANGLE_URL_RE.findall(text):
        found.add(_strip_trailing_punct(m))
    for m in FULL_URL_RE.findall(text):
        found.add(_strip_trailing_punct(m))

    text_wo_full = FULL_URL_RE.sub(" ", text)
    text_wo_full = ANGLE_URL_RE.sub(" ", text_wo_full)
    for m in BARE_DOMAIN_RE.findall(text_wo_full):
        found.add(_strip_trailing_punct(m))
    for m in PROTOCOL_RELATIVE_RE.findall(text_wo_full):
        found.add(_strip_trailing_punct(m))
    return found


def build_url_allowlist(trusted_facts: list[dict]) -> set[str]:
    """Normalize every url/urls field across all trusted facts into one set
    of comparable (scheme-stripped) strings."""
    allowed: set[str] = set()
    for fact in trusted_facts:
        u = fact.get("url")
        if u:
            allowed.add(normalize_url(u))
        for extra in fact.get("urls", []) or []:
            allowed.add(normalize_url(extra))
    return allowed


def check_urls(text: str, trusted_facts: list[dict]) -> list[str]:
    """Every URL-shaped token found in `text` must normalize to something in
    the trusted facts' url/urls fields. Returns a list of human-readable
    error strings (empty list = all URLs traced back to source)."""
    allowed = build_url_allowlist(trusted_facts)
    errors = []
    for u in extract_urls(text):
        if normalize_url(u) not in allowed:
            errors.append(f"untraceable URL/domain not in trusted facts: {u!r}")
    return errors


# --------------------------------------------------------------------------
# 3. Entity + numeric-claim verification — catches bold AND non-bold mentions
# --------------------------------------------------------------------------

# Default entity shape: "owner/repo"-style slug.
#
# Deliberately NOT anchored on `\b` + ASCII character classes. Python's `\b`
# treats every Unicode letter as a "word" character, so a mixed-script token
# like "fakеorg/repo" (Cyrillic 'е' standing in for Latin 'e') has NO
# word-boundary between the Cyrillic letter and the following ASCII "org" —
# both sides are "word" characters as far as `\b` is concerned — so the old
# `\b([A-Za-z0-9][A-Za-z0-9._-]*/...)\b` pattern silently failed to match the
# token at all and the fabricated entity slipped through unflagged. That's a
# bypass, not a false negative in a character class.
#
# Fix, chosen deliberately over Unicode NFKC normalization: NFKC only folds
# *compatibility* variants of characters (full-width forms, ligatures, etc.)
# — it does NOT fold cross-script look-alikes. Cyrillic 'е' (U+0435) and
# Latin 'e' (U+0065) are canonically distinct letters in different scripts;
# NFKC leaves them exactly as they are. Actually solving homoglyph spoofing
# in general requires a confusables-skeleton algorithm (Unicode TR39), which
# is a much bigger dependency than this library wants. Instead we detect
# entity-shaped tokens using boundary characters (whitespace and common
# punctuation) rather than `\b`, so a mixed-script token IS captured as a
# candidate mention — and then explicitly reject/flag any such mention that
# contains a non-ASCII character, since trusted fact `id`s are documented to
# be plain ASCII. This can't be evaded by choosing a different script.
# Includes standard ASCII punctuation (, . ; : ! ?) as valid delimiters, on
# top of whitespace/brackets/quotes/fullwidth punctuation and the numeric
# marker symbols (★ $ #) — this was a real regression: an earlier version
# omitted plain ASCII punctuation, so a trailing comma/semicolon got pulled
# INTO the token ("openai/whisper," misread as a fabricated entity because
# of the trailing comma), and a marker glued directly onto the name with no
# space ("openai/whisper★71234") got pulled in too, tripping the non-ASCII
# check on ★ itself even though the entity name "openai/whisper" was fine.
_ENTITY_BOUNDARY = ' \t\n\r\f\v()[]<>*`"\'　，。！？；：、「」『』（）,.;:!?★$#'
_ENTITY_TOKEN_CHARS = r"[^" + re.escape(_ENTITY_BOUNDARY) + r"/]"
DEFAULT_ENTITY_RE = re.compile(
    r"(" + _ENTITY_TOKEN_CHARS + r"+/" + _ENTITY_TOKEN_CHARS + r"+)"
)

# A number, preceded by a marker symbol (★ $ # etc.). The marker is
# deliberately REQUIRED, not optional: an earlier version made it optional,
# so on a line like "**openai/whisper** was founded in 2015, has ★71234
# stars" the search would grab the first bare number it saw ("2015") as the
# "claimed" metric value — a plain year in prose being misread as a star
# count and flagged as a false-positive mismatch. Requiring an explicit
# marker means "no marker present" is a documented limitation (see README
# Known Limitations), not a silent wrong-number guess.
#
# The digit-group format is also deliberately strict: `\d{1,3}(?:,\d{3})*`
# only accepts real thousands-grouping (groups of exactly three digits after
# the first). An earlier looser pattern (`[\d][\d,]*`) accepted arbitrary
# comma placement, so "★7,1,2,3,4" was silently reinterpreted as 71234 after
# stripping commas — letting a claim dodge scrutiny by dressing up any digit
# sequence as a "formatted" number. With the strict pattern, "7,1,2,3,4"
# only matches as far as "7" (a valid 1-3 digit group), so the claim is read
# literally as 7 and correctly flagged as a mismatch against the real value
# instead of silently reassembling into the number the attacker wanted.
NUMBER_RE = re.compile(r"[★$#]\s?((?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d+)?)")


def _to_number(s: str) -> float:
    return float(s.replace(",", ""))


def _contains_non_ascii(s: str) -> bool:
    return any(ord(c) > 127 for c in s)


def _blank_urls(text: str) -> str:
    """Replace every URL-shaped span (full, angle-wrapped, protocol-relative,
    bare-domain-with-path) with spaces of the same length, so that entity
    matching never fires on a slash-separated fragment of a URL's path
    (e.g. the '2026/09' inside a news URL)."""
    text = ANGLE_URL_RE.sub(lambda m: " " * len(m.group(0)), text)
    text = FULL_URL_RE.sub(lambda m: " " * len(m.group(0)), text)
    text = BARE_DOMAIN_RE.sub(lambda m: " " * len(m.group(0)), text)
    text = PROTOCOL_RELATIVE_RE.sub(lambda m: " " * len(m.group(0)), text)
    return text


def extract_entity_mentions(
    text: str, entity_pattern: re.Pattern = DEFAULT_ENTITY_RE
) -> list[str]:
    """Find every entity-shaped mention in `text`, per line, regardless of
    markdown bold formatting. This is deliberately *not* limited to
    `**bold**` tokens — a fabricated claim that simply skips the bold
    markup, or is mentioned mid-sentence with no attached URL, must still be
    caught. URL-shaped spans are blanked out first so a URL's own path
    segments are never mistaken for an entity mention."""
    mentions = []
    for line in _blank_urls(text).split("\n"):
        for m in entity_pattern.finditer(line):
            mentions.append(m.group(1))
    return mentions


def check_entities_and_metrics(
    text: str,
    trusted_facts: list[dict],
    metric_key: Optional[str] = None,
    tolerance_pct: float = 1.0,
    entity_pattern: re.Pattern = DEFAULT_ENTITY_RE,
) -> list[str]:
    """For every entity-shaped mention in `text` (bold or not):
      - it must exist in trusted_facts by `id`, else it's flagged as a
        fabricated/unknown entity;
      - if it contains any non-ASCII character, it's flagged outright as a
        possible homoglyph/confusable spoofing attempt, regardless of
        whether it happens to string-match a trusted id — trusted fact
        `id`s are documented to be plain ASCII, so a look-alike using
        Cyrillic/Greek/fullwidth letters etc. has no legitimate reason to
        appear here;
      - if `metric_key` is given and the same line also carries a
        marker-prefixed number (e.g. ★1234), that number must match
        trusted_facts[id]["metrics"][metric_key] within `tolerance_pct`
        percent, else it's flagged as a numeric mismatch (a real name
        attached to a fake number is still fake).
    """
    by_id = {f["id"]: f for f in trusted_facts}
    errors: list[str] = []
    for orig_line, blanked_line in zip(text.split("\n"), _blank_urls(text).split("\n")):
        line = orig_line  # keep original for the trailing number lookup
        for m in entity_pattern.finditer(blanked_line):
            name = m.group(1)
            if _contains_non_ascii(name):
                errors.append(
                    f"entity mention contains non-ASCII characters "
                    f"(possible homoglyph/confusable spoofing attempt): {name!r}"
                )
                continue
            if name not in by_id:
                errors.append(
                    f"fabricated/unknown entity reference (not in trusted facts): {name!r}"
                )
                continue
            if metric_key is None:
                continue
            record = by_id[name]
            actual = (record.get("metrics") or {}).get(metric_key)
            if actual is None:
                continue
            num_m = NUMBER_RE.search(line, m.end())
            if not num_m:
                continue
            claimed = _to_number(num_m.group(1))
            tol = max(1.0, abs(actual) * tolerance_pct / 100.0)
            if abs(claimed - actual) > tol:
                errors.append(
                    f"numeric mismatch for {name!r}: claimed {claimed}, "
                    f"source has {metric_key}={actual} (tolerance ±{tol})"
                )
    return errors


# --------------------------------------------------------------------------
# 4. Secret scanning — strict per-provider shape
#
# NOT a claim of zero false positives/negatives against every real-world key
# format that exists or will exist — that would be overclaiming. It covers
# the specific formats listed below, matched on real structural markers
# rather than punctuation heuristics, and the two concrete
# false-positive/false-negative bugs found during review (see README) are
# fixed. New provider formats (OpenAI alone has added `sk-svcacct-` service
# account keys and a `sk-None-` shape seen when an org id is unset) need
# their own pattern added here; anything not listed is a documented gap —
# see README "Known Limitations".
# --------------------------------------------------------------------------

# NOTE on the "no hyphens in the key body" idea: that is NOT a rule real
# keys actually follow, and an earlier version of this file wrongly said it
# was. OpenAI's legacy `sk-...` keys ARE a contiguous alnum/underscore run,
# but OpenAI's newer `sk-proj-...` project keys legitimately DO contain
# hyphens and underscores in the body — a blanket "reject hyphens" rule
# would false-negative on real sk-proj- keys. What actually distinguishes
# the "sk-hynix-reportedly-expands-hbm-output" false-positive case (a real
# news URL slug, not a key) from a genuine key is NOT punctuation — it's the
# literal `proj-` marker plus length. So the two OpenAI variants are matched
# separately:
#   - legacy `sk-...`: requires a `proj-` NOT to follow, and (matching real
#     legacy key shape) a long contiguous alnum run with no hyphen — this is
#     still correct for the *legacy* format specifically, and "hynix-..."
#     fails it after 5 chars because of the hyphen, same as before;
#   - `sk-proj-...`: requires the literal `proj-` marker right after `sk-`,
#     then allows hyphens/underscores in the body (matching the real
#     format) — "sk-hynix..." never reaches this branch at all because it
#     doesn't contain the literal substring `proj-` after `sk-`.
# This distinguishes on a real structural marker instead of a punctuation
# heuristic that happened to be false.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OpenAI API key (legacy sk-)", re.compile(r"\bsk-(?!proj-|svcacct-|None-)[A-Za-z0-9]{20,}\b")),
    ("OpenAI API key (sk-proj-)", re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API key (sk-svcacct-, service account)", re.compile(r"\bsk-svcacct-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API key (sk-None-, unset org id)", re.compile(r"\bsk-None-[A-Za-z0-9_-]{20,}\b")),
    ("Anthropic API key (sk-ant-)", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp_|gho_|github_pat_)[A-Za-z0-9_]{20,}\b")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[bp]-[A-Za-z0-9-]{10,}\b")),
    ("PEM private key block", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
    ("JWT-like token", re.compile(r"\beyJ[A-Za-z0-9_=]{10,}\.[A-Za-z0-9_=]{10,}\.[A-Za-z0-9_=-]{10,}\b")),
]

_ENV_SECRET_NAME_RE = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD)", re.IGNORECASE)


def redact(s: str) -> str:
    if len(s) <= 14:
        return "[REDACTED]"
    return f"{s[:6]}…[REDACTED,{len(s)} chars]…{s[-4:]}"


def scan_secrets(text: str, check_env: bool = True) -> list[str]:
    """Scan `text` for anything that looks like a leaked credential: known
    provider key shapes, PEM blocks, JWT-looking tokens, and (optionally)
    the literal value of any currently-set environment variable whose name
    contains KEY/TOKEN/SECRET/PASSWORD. Findings are redacted before being
    returned — never echo the full secret back into a log."""
    findings = []
    for name, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            findings.append(f"possible {name}: {redact(m.group(0))}")
    if check_env:
        for k, v in os.environ.items():
            if not v or len(v) < 8:
                continue
            if not _ENV_SECRET_NAME_RE.search(k):
                continue
            if v in text:
                findings.append(f"environment variable ${{{k}}} value found in output: {redact(v)}")
    return findings


def _scrub_allowed_urls_for_secret_scan(text: str, trusted_facts: list[dict]) -> str:
    """Blank out any URL that's already in the trusted allowlist before
    secret-scanning, so a real, legitimate URL (which may contain a
    hyphenated substring that superficially resembles a key fragment, e.g.
    '.../sk-hynix-reportedly-...') can never trigger a false positive."""
    allowed = build_url_allowlist(trusted_facts)

    def is_allowed(u: str) -> bool:
        return normalize_url(u) in allowed

    def repl_angle(m: re.Match) -> str:
        return " " * len(m.group(0)) if is_allowed(m.group(1)) else m.group(0)

    def repl_plain(m: re.Match) -> str:
        return " " * len(m.group(0)) if is_allowed(m.group(0)) else m.group(0)

    text = ANGLE_URL_RE.sub(repl_angle, text)
    text = FULL_URL_RE.sub(repl_plain, text)
    return text


# --------------------------------------------------------------------------
# 5. Top-level verify()
# --------------------------------------------------------------------------


def verify(
    output_text: str,
    trusted_facts: list[dict],
    source_file_path: Optional[str] = None,
    source_sha256_before: Optional[str] = None,
    metric_key: Optional[str] = None,
    tolerance_pct: float = 1.0,
    entity_pattern: re.Pattern = DEFAULT_ENTITY_RE,
    check_env_secrets: bool = True,
) -> VerifyResult:
    """Run the full check suite against LLM-generated `output_text`.

    Args:
        output_text: the LLM's generated text to verify.
        trusted_facts: list of fact records built from a source YOU control,
            captured BEFORE the LLM ran (see module docstring for schema).
        source_file_path / source_sha256_before: if both given, re-hashes
            source_file_path and fails if it doesn't match the hash you
            captured before the run — proof the agent didn't tamper with
            ground truth.
        metric_key: which key inside each fact's "metrics" dict to check
            claimed numbers against (e.g. "stars"). None disables numeric
            checking (still checks entity existence and URLs).
        tolerance_pct: allowed percent difference for numeric claims.
        entity_pattern: regex with one capture group identifying an
            entity-shaped mention. Override for non-repo-shaped domains.
        check_env_secrets: also flag any live env var (KEY/TOKEN/SECRET/
            PASSWORD in its name) whose value appears verbatim in the text.

    Returns:
        VerifyResult(ok, errors) — ok is False if ANY check fails.
    """
    errors: list[str] = []

    if source_file_path is not None and source_sha256_before is not None:
        matches, actual = verify_integrity(source_file_path, source_sha256_before)
        if not matches:
            errors.append(
                f"source-of-truth file changed during the run — sha256 was "
                f"{source_sha256_before[:12]}…, is now {actual[:12]}… "
                f"({source_file_path}); nothing downstream can be trusted"
            )

    errors.extend(check_urls(output_text, trusted_facts))
    errors.extend(
        check_entities_and_metrics(
            output_text,
            trusted_facts,
            metric_key=metric_key,
            tolerance_pct=tolerance_pct,
            entity_pattern=entity_pattern,
        )
    )

    scrubbed = _scrub_allowed_urls_for_secret_scan(output_text, trusted_facts)
    errors.extend(scan_secrets(scrubbed, check_env=check_env_secrets))

    return VerifyResult(ok=(len(errors) == 0), errors=errors)
