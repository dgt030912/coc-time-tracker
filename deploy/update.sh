#!/bin/bash
# Pulls the latest code; if anything changed, re-runs setup so the server restarts with it.
set -euo pipefail
APP=/srv/coc
before=$(git -C "$APP" rev-parse HEAD)
git -C "$APP" pull -q --ff-only
after=$(git -C "$APP" rev-parse HEAD)
if [ "$before" != "$after" ]; then
  bash "$APP/deploy/setup.sh"
fi
