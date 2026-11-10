# CoC Time Tracker

Tracks Clash of Clans upgrade timers across all your villages. Paste a village export (the JSON from the game's settings) and it shows a live countdown and finish time for every running builder, lab and pet upgrade. Data is stored on the server per login, so every device sees the same villages.

## Run it locally

```bash
printf 'yourpassword\n' | DATA_DIR=./data python3 server.py adduser yourname --password-stdin
PORT=8765 COOKIE_SECURE=0 DATA_DIR=./data python3 server.py
```

Then open http://localhost:8765. Python 3 standard library only; no dependencies.

## Files

- `server.py`: backend. Login, sessions and per-user storage as JSON files in `$DATA_DIR`.
- `index.html`: the app. `login.html`: sign-in page. Both are only served by `server.py`.
- `game-names.json`: data ID → in-game name mapping used to label upgrades.
- `deploy/`: VM setup. `startup.sh` is the GCE startup script, `setup.sh` installs Caddy (HTTPS) and the systemd service, `update.sh` pulls from GitHub every 5 minutes and restarts on changes.

Storage layout in `$DATA_DIR` (never committed):

| File | Contents |
|---|---|
| `users.json` | username → salted PBKDF2-SHA256 password hash |
| `sessions.json` | SHA-256 of each session token → user and expiry (30 days) |
| `users/<name>.json` | that user's villages (export, nickname, boosts) and item names |

Usernames and passwords are case-insensitive. Failed logins are rate-limited per IP.

## Using it

- **Paste an export** with ⌘V anywhere on the page, or the "Paste export" button. Each export is matched to its village by player tag: a known tag updates that village, a new tag adds one.
- **All villages** shows every upgrade together, with grouping (by village or queue), sorting (soonest, latest, most recent export, village, name) and queue filters.
- **Rename a village** by clicking its name, or clicking its tab when it's already selected.
- **Boosts for this village** lists every boost with time left, set by hand ("45m", "1h 20m", "3d 4h") or read from the export.

## Timing model

- Export `timer` values are seconds of work left at normal speed, counted from the export's `timestamp`.
- **Speed boosts** last 1 hour and add up while they overlap on the same queue: Builder Potion 10×, Builder Byte 4× (both 14×), Research Potion 24×, Study Soup 4×, Pet Potion 24×. A running boost in the export (`boosts.builder_boost`, seconds left) is read in automatically and overwrites the hand-set value.
- **Time cuts** multiply together: Welcome Back −50% (builder, lab, pets), Hammer Jam −50% (builder), Gold Pass −20% (builder, lab, pets). The game applies these when an upgrade starts, so by default they only affect the planner.
