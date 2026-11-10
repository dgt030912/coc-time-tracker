# CoC Time Tracker

A single-page tracker for Clash of Clans upgrade timers. Paste a village export (the JSON from the game's settings) and it shows a live countdown and finish time for every running builder, lab and pet upgrade.

## Run it

```bash
python3 -m http.server 8765 --bind 127.0.0.1
```

Then open http://localhost:8765. The page is plain HTML and JS with no dependencies.

## Using it

- **Paste an export** with ⌘V anywhere on the page, or the "Paste export" button. Each export is matched to its village by player tag: a known tag updates that village, a new tag adds one.
- **All villages** shows every upgrade together, with grouping (by village or queue), sorting (soonest, latest, most recent export, village, name) and queue filters.
- **Per village**: speed boosts, duration cuts and a planner for new upgrades.
- Item and village names can be renamed by clicking them.

Everything is saved in the browser's localStorage. Nothing leaves your machine.

## Timing model

- Export `timer` values are treated as seconds of work left at normal speed, counted from the export's `timestamp`.
- **Speed boosts** last 1 hour and add up while they overlap: Builder Potion 10×, Builder Byte 4× (both together 14×), Research Potion 24×, Pet Potion 24×. A running boost in the export (`boosts.builder_boost`, seconds left) is included automatically.
- **Duration cuts** multiply together: Welcome Back −50% (builder, lab, pets), Hammer Jam −50% (builder), Gold Pass −20% (builder, lab, pets). The game applies these when an upgrade starts, so by default they only affect the planner.
