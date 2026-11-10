#!/bin/bash
# GCE startup script (set as the VM's "startup-script" metadata). Fetches the repo and runs setup on every boot.
set -euo pipefail
if [ ! -d /srv/coc/.git ]; then
  command -v git >/dev/null || { apt-get update -q; DEBIAN_FRONTEND=noninteractive apt-get install -y -q git; }
  git clone -q https://github.com/dgt030912/coc-time-tracker.git /srv/coc
fi
git -C /srv/coc pull -q --ff-only || true
bash /srv/coc/deploy/setup.sh
