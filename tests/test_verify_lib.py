"""Real regression tests for verify_lib, one per documented bypass.

Each test name says which bug it reproduces. Every one of these is written
to demonstrate a failure mode described in the README's incident history —
run them against a deliberately-naive checker (see the comments) and they
fail; run them against verify_lib and they pass, because the fix for each
bypass is built into the corresponding check function.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import verify_lib as vl

TRUSTED_FACTS = [
    {
        "id": "openai/whisper",
        "url": "https://github.com/openai/whisper",
        "metrics": {"stars": 71234},
    },
    {
        "id": "anthropics/claude-code",
        "url": "https://github.com/anthropics/claude-code",
        "metrics": {"stars": 30500},
    },
]


# --------------------------------------------------------------------------
# Bug 3a: bold-less / no-URL fake entity bypasses a naive "check bold or
# URL-shaped tokens only" allowlist.
# --------------------------------------------------------------------------


def test_non_bold_fake_entity_with_star_count_is_caught():
    # Deliberately NOT markdown-bolded (no **...**) — this is the specific
    # bypass: a naive checker that only looks at bolded/URL-shaped tokens
    # lets an unbolded fabricated claim straight through.
    text = "New this week: fakeorg/fakerepo（★50000）is trending fast."
    result = vl.verify(text, TRUSTED_FACTS, metric_key="stars")
    assert not result.ok
    assert any("fakeorg/fakerepo" in e for e in result.errors)


def test_bold_fake_entity_with_star_count_is_also_caught():
    # Same fabrication, this time WITH bold markup, to confirm bolding one
    # way or the other never changes the outcome.
    text = "New this week: **fakeorg/fakerepo**（★50000）is trending fast."
    result = vl.verify(text, TRUSTED_FACTS, metric_key="stars")
    assert not result.ok
    assert any("fakeorg/fakerepo" in e for e in result.errors)


def test_fake_entity_mentioned_mid_sentence_no_url_is_caught():
    text = "Also worth a look: people are talking about fakeorg/fakerepo lately."
    result = vl.verify(text, TRUSTED_FACTS)
    assert not result.ok
    assert any("fakeorg/fakerepo" in e for e in result.errors)


def test_real_entity_correctly_bolded_with_correct_stars_passes():
    text = "**openai/whisper**（★71234）remains the top pick."
    result = vl.verify(text, TRUSTED_FACTS, metric_key="stars")
    assert result.ok, result.errors


# --------------------------------------------------------------------------
# Bug (Opus review round): Unicode homoglyph bypass. `\b` in Python's `re`
# treats every Unicode letter as a "word" character, so a mixed-script
# token like "fakеorg/repo" (Cyrillic 'е', U+0435, standing in for
# Latin 'e') has no word-boundary between the Cyrillic letter and the
# following ASCII letters — the old `\b`-anchored, ASCII-only entity regex
# simply never matched the token, so it passed through unflagged. Fixed by
# matching entity-shaped tokens on punctuation/whitespace boundaries instead
# of `\b`, then explicitly flagging any resulting mention that contains a
# non-ASCII character.
# --------------------------------------------------------------------------


def test_cyrillic_homoglyph_entity_is_caught():
    # This is the exact reproduction case from review: "fakеorg/repo"
    # uses Cyrillic 'е' (U+0435) where a Latin 'e' would normally be.
    fake_org = "fak" + "е" + "org/repo"
    text = f"Huge news: {fake_org} just hit ★5 stars overnight."
    result = vl.verify(text, TRUSTED_FACTS)
    assert not result.ok
    assert any("non-ASCII" in e or "homoglyph" in e for e in result.errors)


def test_ascii_only_real_entity_is_not_flagged_as_homoglyph():
    text = "**openai/whisper**（★71234） remains popular."
    errors = vl.check_entities_and_metrics(text, TRUSTED_FACTS)
    assert not any("non-ASCII" in e or "homoglyph" in e for e in errors)


# --------------------------------------------------------------------------
# Bug 3b: protocol-relative URL (//evil.example.com) bypasses a naive
# `https://`-prefix-only check.
# --------------------------------------------------------------------------


def test_protocol_relative_url_not_in_allowlist_is_caught():
    text = "See details at //evil.example.com/steal for more."
    errors = vl.check_urls(text, TRUSTED_FACTS)
    assert any("evil.example.com" in e for e in errors)


def test_scheme_less_bare_domain_not_in_allowlist_is_caught():
    text = "Full writeup: evil.example.com/phish/path has more."
    errors = vl.check_urls(text, TRUSTED_FACTS)
    assert any("evil.example.com" in e for e in errors)


def test_allowlisted_url_in_full_scheme_less_and_protocol_relative_forms_all_pass():
    for u in (
        "https://github.com/openai/whisper",
        "github.com/openai/whisper",
        "//github.com/openai/whisper",
    ):
        errors = vl.check_urls(f"Reference: {u}", TRUSTED_FACTS)
        assert errors == [], f"{u!r} incorrectly flagged: {errors}"


# --------------------------------------------------------------------------
# Bug 3c-i: secret scanner false positive on real URL containing "sk-hynix".
# --------------------------------------------------------------------------


def test_sk_hynix_real_url_does_not_false_positive():
    facts = TRUSTED_FACTS + [
        {
            "id": "news/sk-hynix-story",
            "url": "https://techcrunch.com/2026/09/sk-hynix-reportedly-expands-hbm-output",
        }
    ]
    text = (
        "**news/sk-hynix-story** — SK Hynix expands output, "
        "https://techcrunch.com/2026/09/sk-hynix-reportedly-expands-hbm-output"
    )
    result = vl.verify(text, facts)
    assert result.ok, result.errors


def test_hyphenated_lookalike_outside_allowlist_still_not_flagged_as_secret():
    # Even off-allowlist, a hyphenated string is not a valid key SHAPE for
    # any of our providers (real keys are contiguous alnum/underscore), so
    # the secret scanner specifically must not fire on it (it will instead
    # be flagged separately as an untraceable URL/domain, which is correct).
    text = "random-looking-token: sk-hynix-not-a-real-key-at-all-1234567890"
    findings = vl.scan_secrets(text)
    assert findings == []


# --------------------------------------------------------------------------
# Bug 3c-ii: secret scanner false negative on Anthropic-format key because
# only OpenAI-style sk- was covered.
# --------------------------------------------------------------------------


def test_anthropic_key_format_is_detected():
    fake_key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
    text = f"Oops, leaked credential: {fake_key}"
    findings = vl.scan_secrets(text)
    assert any("Anthropic" in f for f in findings)


def test_openai_key_format_is_still_detected():
    fake_key = "sk-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
    text = f"Oops, leaked credential: {fake_key}"
    findings = vl.scan_secrets(text)
    assert any("OpenAI" in f for f in findings)


def test_openai_sk_proj_key_with_hyphens_and_underscores_is_detected():
    # Real OpenAI sk-proj- project keys legitimately contain hyphens and
    # underscores in the body (unlike legacy sk- keys). An earlier version
    # of this file wrongly assumed NO real key ever has a hyphen in its
    # body, which would have false-negatived on exactly this shape.
    fake_key = "sk-proj-" + "AbCdEfGh12345678-XyZ90123456789_QwErTy00"
    text = f"Oops, leaked credential: {fake_key}"
    findings = vl.scan_secrets(text)
    assert any("sk-proj" in f for f in findings), findings


def test_sk_hynix_real_url_still_not_flagged_after_sk_proj_fix():
    # Re-verify the original false-positive fix still holds now that the
    # sk- pattern has been split into legacy/proj- variants: neither
    # variant should match a real news URL slug that merely starts with
    # "sk-" and is not actually "proj-".
    text = "https://techcrunch.com/2026/09/sk-hynix-reportedly-expands-hbm-output"
    findings = vl.scan_secrets(text)
    assert findings == [], findings


def test_github_aws_slack_pem_jwt_all_detected():
    samples = {
        "GitHub token": "ghp_" + "a" * 36,
        "AWS access key id": "AKIA" + "Q" * 16,
        "Slack token": "xoxb-" + "1234567890123",
        "PEM private key block": "-----BEGIN RSA PRIVATE KEY-----",
        "JWT-like token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQxxxxxxxxxx",
    }
    for label, secret in samples.items():
        findings = vl.scan_secrets(f"leaked: {secret}")
        assert findings, f"expected a finding for {label} ({secret!r}) but got none"


def test_env_var_secret_value_leak_detected():
    os.environ["TEST_FAKE_API_KEY"] = "supersecretvalue123456"
    try:
        findings = vl.scan_secrets("the value is supersecretvalue123456 right there")
        assert any("TEST_FAKE_API_KEY" in f for f in findings)
    finally:
        del os.environ["TEST_FAKE_API_KEY"]


# --------------------------------------------------------------------------
# Bug 3d: claimed numeric fact (star count) doesn't match the source record.
# --------------------------------------------------------------------------


def test_star_count_mismatch_is_caught():
    text = "**openai/whisper**（★999999999）is huge."
    errors = vl.check_entities_and_metrics(text, TRUSTED_FACTS, metric_key="stars")
    assert any("numeric mismatch" in e and "openai/whisper" in e for e in errors)


def test_star_count_within_tolerance_passes():
    # source has 71234; 1% tolerance allows a small rounding difference
    text = "**openai/whisper**（★71200）is huge."
    errors = vl.check_entities_and_metrics(text, TRUSTED_FACTS, metric_key="stars")
    assert errors == [], errors


def test_star_count_exact_match_passes():
    text = "**openai/whisper**（★71234）is huge."
    errors = vl.check_entities_and_metrics(text, TRUSTED_FACTS, metric_key="stars")
    assert errors == []


def test_malformed_comma_grouping_not_silently_reassembled():
    # An earlier NUMBER_RE ([\d][\d,]*) accepted ANY comma placement and
    # stripped commas blindly, so "★7,1,2,3,4" silently became the number
    # 71234 after stripping — i.e. a claim dressed up with bogus comma
    # placement could dodge the mismatch check entirely. The fixed pattern
    # only accepts real thousands-grouping (groups of exactly 3 digits), so
    # "7,1,2,3,4" is read as the literal number 7 (a valid 1-3 digit group,
    # with the malformed remainder simply not part of the match) and
    # correctly flagged as a mismatch against the real value 71234.
    text = "**openai/whisper**（★7,1,2,3,4）is huge."
    errors = vl.check_entities_and_metrics(text, TRUSTED_FACTS, metric_key="stars")
    assert any("numeric mismatch" in e and "claimed 7.0" in e for e in errors), errors


def test_year_in_prose_is_not_misread_as_star_count():
    # An earlier version made the ★/$/# marker OPTIONAL, so on a line
    # mentioning both a real entity and an unrelated bare number (like a
    # founding year), NUMBER_RE would grab the first bare digit run it saw
    # ("2015") as if it were the claimed metric value, producing a bogus
    # mismatch against the real star count. The marker is now required, so
    # a bare year is never picked up as a metric claim at all.
    text = "**openai/whisper**, founded in 2015, has ★71234 stars."
    errors = vl.check_entities_and_metrics(text, TRUSTED_FACTS, metric_key="stars")
    assert errors == [], errors


# --------------------------------------------------------------------------
# Bug: sha256 tamper detection — source-of-truth file changed after the LLM
# ran must fail closed, regardless of what the output text claims.
# --------------------------------------------------------------------------


def test_sha256_tamper_after_run_is_detected(tmp_path):
    src = tmp_path / "facts.json"
    src.write_text('{"facts": "original"}', encoding="utf-8")
    before = vl.hash_file(str(src))

    # Simulate the agent (or anything else) modifying the source file after
    # the hash was captured but before verification runs.
    src.write_text('{"facts": "tampered"}', encoding="utf-8")

    result = vl.verify(
        "**openai/whisper**（★71234）is huge.",
        TRUSTED_FACTS,
        source_file_path=str(src),
        source_sha256_before=before,
        metric_key="stars",
    )
    assert not result.ok
    assert any("sha256" in e for e in result.errors)


def test_sha256_unchanged_file_passes_integrity_check(tmp_path):
    src = tmp_path / "facts.json"
    src.write_text('{"facts": "original"}', encoding="utf-8")
    before = vl.hash_file(str(src))

    result = vl.verify(
        "**openai/whisper**（★71234）is huge.",
        TRUSTED_FACTS,
        source_file_path=str(src),
        source_sha256_before=before,
        metric_key="stars",
    )
    assert result.ok, result.errors


# --------------------------------------------------------------------------
# End-to-end sanity: a fully legitimate report passes verify() cleanly.
# --------------------------------------------------------------------------


def test_clean_legitimate_report_passes_end_to_end():
    text = (
        "## Weekly picks\n"
        "**openai/whisper**（★71234） — speech recognition, "
        "https://github.com/openai/whisper\n"
        "**anthropics/claude-code**（★30500） — coding agent, "
        "https://github.com/anthropics/claude-code\n"
    )
    result = vl.verify(text, TRUSTED_FACTS, metric_key="stars")
    assert result.ok, result.errors
