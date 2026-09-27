#!/usr/bin/env python3
"""Runnable, committed evidence that each documented bypass is real.

This script is the canonical place to see "naive implementation gets
bypassed, verify_lib does not" — it does NOT rely on git history (this repo
intentionally keeps a single clean commit, so there is no commit-by-commit
before/after to point to). Run it directly:

    python3 examples/naive_vs_fixed_demo.py

Each naive_* function below is a deliberately simplistic reimplementation of
the kind of check an earlier, unpatched version of this pattern used. Each
one is shown failing on the exact case described in the README, immediately
followed by verify_lib's corresponding real function catching the same
case.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verify_lib as vl

TRUSTED_IDS = {"openai/whisper"}


def banner(title):
    print(f"\n=== {title} ===")


# --------------------------------------------------------------------------
# 1. Bold/URL-only entity check vs. non-bold, no-URL fabrication
# --------------------------------------------------------------------------


def naive_entity_check(text, trusted_ids):
    bold_re = re.compile(r"\*\*([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\*\*")
    return [m.group(1) for m in bold_re.finditer(text) if m.group(1) not in trusted_ids]


banner("1. non-bold fabricated entity")
text = "Also worth a look: people are talking about fakeorg/fakerepo lately."
naive_result = naive_entity_check(text, TRUSTED_IDS)
print(f"naive bold-only checker flags: {naive_result!r}  (BYPASS: finds nothing)")
fixed_result = vl.check_entities_and_metrics(text, [{"id": i} for i in TRUSTED_IDS])
print(f"verify_lib catches: {fixed_result}")
assert naive_result == [] and fixed_result, "expected naive to bypass and verify_lib to catch"


# --------------------------------------------------------------------------
# 2. https://-only URL check vs. protocol-relative link
# --------------------------------------------------------------------------


def naive_url_check(text, allowed):
    url_re = re.compile(r"https://[^\s]+")
    return [m.group(0) for m in url_re.finditer(text) if m.group(0) not in allowed]


banner("2. protocol-relative URL")
text = "See details at //evil.example.com/steal for more."
naive_result = naive_url_check(text, {"https://github.com/openai/whisper"})
print(f"naive https-only checker flags: {naive_result!r}  (BYPASS: finds nothing)")
fixed_result = vl.check_urls(text, [{"id": "openai/whisper", "url": "https://github.com/openai/whisper"}])
print(f"verify_lib catches: {fixed_result}")
assert naive_result == [] and fixed_result, "expected naive to bypass and verify_lib to catch"


# --------------------------------------------------------------------------
# 3. Loose sk- pattern (allows hyphens) false-positives on a real URL
# --------------------------------------------------------------------------


def naive_secret_scan_loose(text):
    return re.findall(r"sk-[A-Za-z0-9-]{10,}", text)


banner("3. loose sk- pattern false-positives on a real URL")
text = "https://techcrunch.com/2026/09/sk-hynix-reportedly-expands-hbm-output"
naive_result = naive_secret_scan_loose(text)
print(f"naive loose pattern flags: {naive_result!r}  (BYPASS: false positive on real URL)")
fixed_result = vl.scan_secrets(text)
print(f"verify_lib flags: {fixed_result}  (correctly empty)")
assert naive_result and fixed_result == [], "expected naive to false-positive, verify_lib to stay clean"


# --------------------------------------------------------------------------
# 4. OpenAI-only pattern misses Anthropic's sk-ant- key format
# --------------------------------------------------------------------------


def naive_secret_scan_openai_only(text):
    return re.findall(r"\bsk-(?!ant-)[A-Za-z0-9_]{20,}\b", text)


banner("4. OpenAI-only pattern misses sk-ant- (Anthropic) keys")
fake_ant_key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
text = f"leaked: {fake_ant_key}"
naive_result = naive_secret_scan_openai_only(text)
print(f"naive OpenAI-only pattern flags: {naive_result!r}  (BYPASS: false negative)")
fixed_result = vl.scan_secrets(text)
print(f"verify_lib flags: {fixed_result}")
assert naive_result == [] and fixed_result, "expected naive to miss it, verify_lib to catch it"


# --------------------------------------------------------------------------
# 5. "no hyphens in key body" rule misses real sk-proj- keys
# --------------------------------------------------------------------------


def naive_secret_scan_no_hyphens_rule(text):
    # This was verify_lib's OWN rule before the Opus review round: reject
    # hyphens in the body entirely, on the (false) theory that real keys
    # never contain them.
    return re.findall(r"\bsk-(?:proj-)?[A-Za-z0-9_]{20,}\b", text)


banner("5. blanket 'no hyphens' rule misses a real sk-proj- key")
fake_proj_key = "sk-proj-" + "AbCdEfGh12345678-XyZ90123456789_QwErTy00"
text = f"leaked: {fake_proj_key}"
naive_result = naive_secret_scan_no_hyphens_rule(text)
print(f"naive no-hyphens-allowed pattern flags: {naive_result!r}  (BYPASS: false negative, hyphen breaks the match early)")
fixed_result = vl.scan_secrets(text)
print(f"verify_lib flags: {fixed_result}")
assert naive_result == [] and fixed_result, "expected naive to miss the real sk-proj- key, verify_lib to catch it"


# --------------------------------------------------------------------------
# 6. ASCII-only, \b-anchored entity regex misses a Unicode homoglyph
# --------------------------------------------------------------------------


def naive_entity_check_ascii_boundary(text, trusted_ids):
    ascii_re = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)\b")
    return [m.group(1) for m in ascii_re.finditer(text) if m.group(1) not in trusted_ids]


banner("6. ASCII \\b-anchored regex misses a Cyrillic homoglyph")
fake_org = "fak" + "е" + "org/repo"  # Cyrillic 'е' (U+0435)
text = f"Huge news: {fake_org} just hit ★5 stars overnight."
naive_result = naive_entity_check_ascii_boundary(text, TRUSTED_IDS)
print(f"naive ASCII \\b-anchored checker flags: {naive_result!r}  (BYPASS: no word-boundary next to non-ASCII letter)")
fixed_result = vl.check_entities_and_metrics(text, [{"id": i} for i in TRUSTED_IDS])
print(f"verify_lib flags: {fixed_result}")
assert naive_result == [] and fixed_result, "expected naive to miss the homoglyph, verify_lib to catch it"

print("\nAll naive-vs-fixed comparisons behaved as documented.")
