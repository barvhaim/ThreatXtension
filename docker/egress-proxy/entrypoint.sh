#!/bin/sh
# Assemble the runtime allowlist: fixed base + provider/LLM hosts from
# EGRESS_ALLOW_EXTRA (comma- or newline-separated regex entries), then start
# tinyproxy against it. Keeps the base immutable while letting the LLM provider
# vary per deployment.
set -eu

BASE=/etc/tinyproxy/allowlist.txt
RUNTIME=/tmp/allowlist.txt

cp "$BASE" "$RUNTIME"

if [ -n "${EGRESS_ALLOW_EXTRA:-}" ]; then
  echo "" >> "$RUNTIME"
  echo "# --- appended from EGRESS_ALLOW_EXTRA ---" >> "$RUNTIME"
  # Split on commas and newlines; trim blanks.
  echo "$EGRESS_ALLOW_EXTRA" | tr ',\n' '\n\n' | while IFS= read -r host; do
    h=$(printf '%s' "$host" | tr -d ' ')
    [ -n "$h" ] && echo "$h" >> "$RUNTIME"
  done
fi

exec tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf
