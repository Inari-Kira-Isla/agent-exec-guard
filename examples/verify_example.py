#!/usr/bin/env python3
"""Minimal end-to-end example of the verify_lib workflow.

1. Build trusted_facts from a source YOU control (here: an inline list, in
   practice usually loaded from a JSON file whose hash you captured before
   running the LLM).
2. Pretend `llm_output` is what came back from your agent.
3. Run verify() and check the result before trusting/publishing the text.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from verify_lib import verify

trusted_facts = [
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

# A clean report: passes.
good_output = (
    "**openai/whisper**（★71234） — speech recognition, "
    "https://github.com/openai/whisper\n"
)

# A fabricated repo slipped in without bold markup or a URL: caught anyway.
bad_output = (
    "**openai/whisper**（★71234） is great, and so is fakeorg/fakerepo which "
    "just hit ★50000 overnight.\n"
)

for label, text in [("good", good_output), ("bad", bad_output)]:
    result = verify(text, trusted_facts, metric_key="stars")
    print(f"[{label}] ok={result.ok}")
    for e in result.errors:
        print(f"  - {e}")
