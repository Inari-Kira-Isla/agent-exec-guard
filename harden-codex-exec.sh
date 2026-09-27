#!/usr/bin/env bash
# harden-codex-exec.sh — run `codex exec` over untrusted input without
# handing it a network connection or code-execution surface it can use to
# escape the task, then fail loud if anything outside the expected event
# types shows up in its structured output log.
#
# WHY THIS EXISTS (see README for the full incident writeup):
#
#   `codex exec -s read-only` blocks filesystem WRITES. It does NOT disable
#   MCP servers or built-in features (apps/connectors, browser_use,
#   computer_use, plugins, multi_agent, image_generation, web_search) from
#   reaching the network or executing code outside the sandbox. A prompt
#   that convinces the model to call a configured MCP tool can exfiltrate
#   data or hit the network even in "read-only" mode.
#
#   Grepping the agent's plain-text log for suspicious keywords is not a
#   security control: legitimate output routinely contains words like
#   "false" or benign status strings, producing false positives, while a
#   real bypass can hide inside otherwise-normal-looking text. The only
#   reliable signal is codex's own STRUCTURED --json event stream, checked
#   against an allowlist of `item.type` values.
#
# WHAT THIS SCRIPT DOES:
#   1. Enumerates every currently-configured MCP server via
#      `codex mcp list --json` and explicitly disables each one by name
#      (`-c mcp_servers.<name>.enabled=false`) — never assumes the config
#      file is the full picture; asks codex directly.
#   2. Disables the built-in features that can reach outside the sandbox:
#      apps, browser_use, computer_use, plugins, multi_agent,
#      image_generation, plus `-c tools.web_search=false`.
#   3. Runs `codex exec -s read-only --json ...` with your prompt/flags,
#      capturing the JSONL event stream to a temp file.
#   4. Parses that JSONL and requires every `item.completed` event's
#      `item.type` to be in the allowlist (default: agent_message,
#      command_execution, error). ANY other type — mcp_tool_call,
#      web_search_call, image_generation_call, or anything unrecognized —
#      is treated as evidence a disabled capability fired anyway, and the
#      whole run is marked BLOCKED (fail closed).
#   5. Requires at least one real `agent_message` event. An empty or
#      truncated log must not pass vacuously just because it also contains
#      no violations.
#
# USAGE:
#   harden-codex-exec.sh [--allowed-types t1,t2,...] [--model NAME] \
#       [-- ] <codex exec flags/prompt...>
#
#   Everything after the recognized wrapper flags (and an optional `--`) is
#   passed straight through to `codex exec`. Prompt text can also be piped
#   on stdin exactly as with plain `codex exec -`.
#
# EXIT CODES:
#   0  = codex ran, event stream is clean, >=1 agent_message seen.
#   1  = BLOCKED: MCP enumeration failed, a disallowed event type appeared,
#        codex itself exited non-zero, or no agent_message was observed.
#   2  = usage error.
#
# ENV VARS:
#   AGENT_EXEC_GUARD_ALLOWED_TYPES   comma-separated override for the
#                                    allowlist (default: agent_message,
#                                    command_execution,error)
#   AGENT_EXEC_GUARD_KEEP_LOG=1      don't delete the temp JSONL log on exit
#                                    (path is printed to stderr either way)
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
ALLOWED_TYPES="${AGENT_EXEC_GUARD_ALLOWED_TYPES:-agent_message,command_execution,error}"
KEEP_LOG="${AGENT_EXEC_GUARD_KEEP_LOG:-0}"
CODEX_BIN="${CODEX_BIN:-codex}"

usage() {
  cat >&2 <<EOF
Usage: ${SCRIPT_NAME} [--allowed-types t1,t2,...] [--dry-run] [--] <codex exec flags/prompt...>

Wraps 'codex exec' with MCP/feature lockdown + structured-event allowlist
verification. See the top of this script for the full rationale.

  --allowed-types t1,t2   comma-separated item.type allowlist
                          (default: ${ALLOWED_TYPES})
  --dry-run               print the exact codex command that would run,
                          without executing it (no API usage)
  --                      everything after this is passed through verbatim
                          to 'codex exec'
EOF
  exit 2
}

DRY_RUN=0
PASSTHROUGH_ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --allowed-types)
      [ "$#" -ge 2 ] || usage
      ALLOWED_TYPES="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      ;;
    --)
      shift
      PASSTHROUGH_ARGS+=("$@")
      break
      ;;
    *)
      PASSTHROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

command -v "${CODEX_BIN}" >/dev/null 2>&1 || {
  echo "BLOCKED: '${CODEX_BIN}' not found on PATH" >&2
  exit 1
}

# --- Step 1: enumerate + disable every configured MCP server ---------------
# Never trust "the config file looked empty" — ask codex directly, and if
# that call itself fails or returns malformed JSON, fail closed rather than
# assuming there's nothing to disable.
MCP_LIST_RAW="$("${CODEX_BIN}" mcp list --json 2>/dev/null)" || {
  echo "BLOCKED: '${CODEX_BIN} mcp list --json' failed; refusing to assume there are no MCP servers to disable" >&2
  exit 1
}
if ! echo "${MCP_LIST_RAW}" | python3 -c "import json,sys; json.load(sys.stdin)" >/dev/null 2>&1; then
  echo "BLOCKED: '${CODEX_BIN} mcp list --json' returned invalid JSON; refusing to assume there are no MCP servers to disable" >&2
  echo "raw output: ${MCP_LIST_RAW}" >&2
  exit 1
fi

# Schema note (verified 2026-09-28 against codex-cli 0.153.4 `codex mcp list
# --json`): every entry currently DOES include an explicit boolean `enabled`
# field. We still don't rely on that holding across every codex-cli version
# forever: any entry where the field is missing/null is treated the same as
# `enabled=true` (disable it) rather than silently skipped — "unknown" fails
# closed towards "disable", never towards "leave it reachable". That said,
# this enumeration step is defense in depth, not the actual backstop: the
# real fail-closed guarantee is step 4 below (the JSON event-type allowlist),
# which catches an mcp_tool_call event regardless of whether this loop
# correctly enumerated/disabled the server that produced it.
MCP_DISABLE_ARGS=()
MCP_DISABLED_COUNT=0
while IFS=$'\t' read -r mcp_name mcp_enabled; do
  [ -n "${mcp_name}" ] || continue
  if [ "${mcp_enabled}" != "False" ] && [ "${mcp_enabled}" != "false" ]; then
    MCP_DISABLE_ARGS+=(-c "mcp_servers.${mcp_name}.enabled=false")
    MCP_DISABLED_COUNT=$((MCP_DISABLED_COUNT + 1))
  fi
done <<<"$(echo "${MCP_LIST_RAW}" | python3 -c "
import json, sys
for x in json.load(sys.stdin):
    print(f\"{x.get('name','')}\t{x.get('enabled')}\")
")"

# --- Step 2: disable built-in features that can reach outside the sandbox --
CAPABILITY_DISABLE_ARGS=(
  --disable apps
  --disable browser_use
  --disable computer_use
  --disable plugins
  --disable multi_agent
  --disable image_generation
  -c "tools.web_search=false"
)

# Note: bash 3.2 (macOS's shipped /bin/bash) raises "unbound variable" under
# `set -u` when expanding "${arr[@]}" on a genuinely empty array — the
# ${arr[@]+"${arr[@]}"} form is the portable way to expand "zero or more
# args" safely across bash 3.2 and 4+.
FULL_ARGS=(
  exec -s read-only --json
  ${MCP_DISABLE_ARGS[@]+"${MCP_DISABLE_ARGS[@]}"}
  ${CAPABILITY_DISABLE_ARGS[@]+"${CAPABILITY_DISABLE_ARGS[@]}"}
  ${PASSTHROUGH_ARGS[@]+"${PASSTHROUGH_ARGS[@]}"}
)

if [ "${DRY_RUN}" = "1" ]; then
  echo "DRY RUN — would execute:" >&2
  printf '  %s' "${CODEX_BIN}" >&2
  for a in "${FULL_ARGS[@]}"; do printf ' %q' "$a" >&2; done
  printf '\n' >&2
  echo "MCP servers disabled: ${MCP_DISABLED_COUNT}" >&2
  exit 0
fi

# --- Step 3: run codex, capturing structured JSONL event output -----------
LOG_FILE="$(mktemp -t agent-exec-guard-codex-log.XXXXXX)"
cleanup() {
  if [ "${KEEP_LOG}" != "1" ]; then
    rm -f "${LOG_FILE}"
  else
    echo "codex JSONL log kept at: ${LOG_FILE}" >&2
  fi
}
trap cleanup EXIT

set +e
"${CODEX_BIN}" "${FULL_ARGS[@]}" >"${LOG_FILE}" 2>&1
CODEX_EXIT=$?
set -e

cat "${LOG_FILE}" >&2

if [ "${CODEX_EXIT}" != "0" ]; then
  echo "BLOCKED: codex exited ${CODEX_EXIT}; not trusting any output from this run" >&2
  exit 1
fi

# --- Step 4+5: verify the structured event stream against the allowlist ----
AGENT_EXEC_GUARD_ALLOWED_TYPES="${ALLOWED_TYPES}" python3 - "${LOG_FILE}" <<'PYEOF'
import json, os, sys

path = sys.argv[1]
allowed = {t.strip() for t in os.environ.get("AGENT_EXEC_GUARD_ALLOWED_TYPES", "").split(",") if t.strip()}
if not allowed:
    print("BLOCKED: empty allowed-types list", file=sys.stderr)
    sys.exit(1)

bad = []
seen_types = set()
agent_message_count = 0
any_line_parsed = False

with open(path, encoding="utf-8", errors="replace") as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except Exception:
            continue
        if evt.get("type") != "item.completed":
            continue
        any_line_parsed = True
        item_type = evt.get("item", {}).get("type")
        seen_types.add(item_type)
        if item_type == "agent_message":
            agent_message_count += 1
        if item_type not in allowed:
            bad.append((i, item_type, json.dumps(evt, ensure_ascii=False)[:300]))

if bad:
    print("BLOCKED: disallowed item.type in codex JSON event stream "
          "(a disabled MCP server or feature may have fired anyway):", file=sys.stderr)
    for i, item_type, snippet in bad:
        print(f"  line {i}: type={item_type} | {snippet}", file=sys.stderr)
    sys.exit(1)

if agent_message_count < 1:
    print("BLOCKED: zero agent_message events in the log (empty or truncated run) "
          "— an empty log must not pass vacuously", file=sys.stderr)
    sys.exit(1)

print(f"OK: all item.completed events within allowlist {sorted(allowed)}; "
      f"observed types={sorted(seen_types)}; agent_message_count={agent_message_count}",
      file=sys.stderr)
PYEOF
