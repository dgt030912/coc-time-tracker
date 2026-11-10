#!/bin/bash
# Pulls the latest code and re-runs setup until the current commit has been deployed successfully.
# The deployed commit is recorded only after setup succeeds, so a failed setup is retried on the next run.
set -euo pipefail
APP=/srv/coc
STAMP=/var/lib/coc-timer-deployed
LOG=/var/log/coc-update.log

git -C "$APP" pull -q --ff-only
head=$(git -C "$APP" rev-parse HEAD)
if [ "$(cat "$STAMP" 2>/dev/null)" != "$head" ]; then
  if bash "$APP/deploy/setup.sh" >>"$LOG" 2>&1; then
    echo "$head" > "$STAMP"
    echo "$(date -u +%FT%TZ) deployed $head" >>"$LOG"
  else
    echo "$(date -u +%FT%TZ) setup FAILED for $head (will retry)" >>"$LOG"
    exit 1
  fi
fi
