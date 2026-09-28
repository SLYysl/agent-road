#!/bin/bash
# Read-only observations. Missing visibility is UNKNOWN, never an install instruction.
printf 'Agent Road read-only Mac inspection\n'
uname -s; uname -m
if [ "$(uname -s)" != Darwin ]; then printf 'UNSUPPORTED_CONTROLLER: inspection only\n'; exit 0; fi
sw_vers
for item in node git python3 tailscale agent-road ssh; do
  if command -v "$item" >/dev/null 2>&1; then command -v "$item"; else printf '%s: NOT_ON_PATH (may exist elsewhere)\n' "$item"; fi
done
if command -v node >/dev/null 2>&1; then node --version; fi
if [ -e "${AGENT_ROAD_HOME:-$HOME/.agent-road}" ]; then printf 'Agent Road state exists: retain, do not overwrite\n'; else printf 'Default/selected state path absent\n'; fi
printf 'Tailscale identity and Serve permissions require separate owner-reviewed read-only inspection. No connectivity claim.\n'
