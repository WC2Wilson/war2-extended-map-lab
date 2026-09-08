# Implementation Status — 0.9.5 stable 256-map baseline

This branch is the preserved runtime-only baseline used for large Warcraft II Remastered maps.

- exact target build verification before writes
- runtime patching only; the installed game executable is not permanently modified
- expanded PUD layer limits and map allocations up to 256×256
- expanded navigation-region storage
- extended minimap/camera handling used by the 0.9.x line
- runtime restore command and static verification tools

The later 0.10/0.11 arbitrary-rectangle experiments are intentionally not merged into this stable branch. They explored broader rectangular-map behavior and introduced regressions relative to the confirmed 256×256 path.
