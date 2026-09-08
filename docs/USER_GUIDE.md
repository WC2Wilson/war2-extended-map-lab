# War2 Extended Map Lab 0.9.5 — User Guide

## Supported game build

This release targets Warcraft II Remastered x86 **1.0.2.2818** and verifies the executable identity before applying runtime changes. An unsupported executable is rejected.

## Basic use

1. Start Warcraft II Remastered.
2. Run `run_extended_map_lab.bat`.
3. Leave the console open while testing.
4. Load a large PUD. The included `maps/Extended_256x256_Test.pud` is the main release test.
5. Exercise the entire map, especially the bottom-right area and the minimap.

The patch is process-local. Closing Warcraft II returns the game to its normal startup state.

## Restore without restarting

Run `restore_running_game.bat`. It invokes the runtime with:

```text
--restore --no-monitor
```

## Useful command-line options

Run the Python file directly for development/testing:

```text
py -3 war2_extended_map_lab.py --dry-run
py -3 war2_extended_map_lab.py --pid <PID>
py -3 war2_extended_map_lab.py --restore --no-monitor
py -3 war2_extended_map_lab.py --self-test-all-sizes
```

- `--dry-run` checks patch locations without writing memory.
- `--pid` attaches to a specific Warcraft II process.
- `--restore` restores supported original bytes/state.
- `--no-monitor` exits after the patch/restore operation.
- `--self-test-all-sizes` runs the offline dimension planner test.

## Recommended 256×256 test order

1. Start a normal 128×128 map and confirm baseline behavior.
2. Apply Extended Map Lab.
3. Load `Extended_256x256_Test.pud`.
4. Move units to all four corners.
5. Build near the lower/right edges.
6. Verify fog and exploration.
7. Verify minimap positions, camera rectangle, and minimap clicks.
8. Save/load where the game mode supports it.
9. Return to a 128×128 map in the same process and check normal behavior.

## Offline tests

The repository includes static and behavioral tests used during development. Run them from the repository root with Python 3.

## Troubleshooting

**Unsupported executable** — verify you are running the supported x86 1.0.2.2818 build.

**Patch location mismatch** — stop and do not force the patch. A changed executable requires a separately verified profile.

**Large map loads but behaves incorrectly** — reproduce first with the included 256×256 test map so map-file issues can be separated from runtime issues.
