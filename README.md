# War2 Extended Map Lab 0.9.5

Runtime large-map support for **Warcraft II Remastered x86 1.0.2.2818**, with the confirmed 256×256 map path preserved as the stable release target.

## Features

- Enables extended PUD map layers through 256×256.
- Expands the required runtime map and navigation buffers.
- Handles the 256×256 minimap scale and map-size-dependent transfer lengths.
- Applies changes only to the running Warcraft II process.
- Verifies the exact supported executable before writing memory.
- Provides `--dry-run` verification and runtime restore support.
- Includes generated test PUDs and offline validation tests.

## Quick start

1. Start Warcraft II Remastered **1.0.2.2818 x86**.
2. Double-click `run_extended_map_lab.bat`.
3. Load `maps/Extended_256x256_Test.pud` or a 256×256 PUD created with PUD Studio.
4. Test movement, building placement, fog/vision, minimap clicks, and save/load behavior.
5. Close Warcraft II when finished; the runtime changes disappear with the process.

To restore the supported code bytes without closing the current game process, run `restore_running_game.bat`.

See [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) for verification, command-line options, test order, and troubleshooting.

## Stable branch note

0.9.5 is the stable large-map branch used for this repository. Later experimental branches explored broader rectangular-storage changes and are not part of this release.

## License

MIT. See [`LICENSE`](LICENSE).
