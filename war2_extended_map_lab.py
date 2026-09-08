from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
from dataclasses import dataclass
import struct
import sys
import time

TARGET_EXE = "Warcraft II.exe"
EXPECTED_SHA256 = "1a396a77b123bbae46c6a2d92adc2ec6714134c24023ed8218f7a160a80ec162"
EXPECTED_TIMESTAMP = 0x699E13E7
EXPECTED_IMAGE_SIZE = 0x62B000
EXPECTED_VERSION = "1.0.2.2818"
LAB_VERSION = "0.9.5"

# Validated arbitrary-dimension model. Warcraft II still keeps one native
# square storage dimension, so the retrofit tracks three independent values:
# logical width (X bounds), logical height (Y bounds), and storage stride.
MIN_LOGICAL_DIM = 1
MAX_LOGICAL_DIM = 256
MIN_STORAGE_SIDE = 32
STORAGE_QUANTUM = 32
MAX_STORAGE_SIDE = 256

@dataclass(frozen=True)
class DimensionPlan:
    width: int
    height: int
    stride: int
    compact_cells: int
    storage_cells: int
    byte_size: int
    word_size: int
    dword_size: int
    padding_cells: int


def dimension_plan(width: int, height: int) -> DimensionPlan:
    if not (MIN_LOGICAL_DIM <= width <= MAX_LOGICAL_DIM):
        raise ValueError(f"width must be {MIN_LOGICAL_DIM}..{MAX_LOGICAL_DIM}, got {width}")
    if not (MIN_LOGICAL_DIM <= height <= MAX_LOGICAL_DIM):
        raise ValueError(f"height must be {MIN_LOGICAL_DIM}..{MAX_LOGICAL_DIM}, got {height}")
    stride = max(MIN_STORAGE_SIDE, width, height)
    stride = (stride + STORAGE_QUANTUM - 1) & ~(STORAGE_QUANTUM - 1)
    if stride > MAX_STORAGE_SIDE:
        raise ValueError(f"calculated storage stride {stride} exceeds {MAX_STORAGE_SIDE}")
    compact_cells = width * height
    storage_cells = stride * stride
    return DimensionPlan(
        width=width,
        height=height,
        stride=stride,
        compact_cells=compact_cells,
        storage_cells=storage_cells,
        byte_size=storage_cells,
        word_size=storage_cells * 2,
        dword_size=storage_cells * 4,
        padding_cells=storage_cells - compact_cells,
    )


def exhaustive_dimension_self_test() -> dict[str, int]:
    checked = 0
    max_padding = 0
    stride_counts: dict[int, int] = {}
    for width in range(MIN_LOGICAL_DIM, MAX_LOGICAL_DIM + 1):
        for height in range(MIN_LOGICAL_DIM, MAX_LOGICAL_DIM + 1):
            plan = dimension_plan(width, height)
            assert plan.stride % STORAGE_QUANTUM == 0
            assert plan.stride >= width and plan.stride >= height
            assert plan.storage_cells <= MAX_STORAGE_SIDE * MAX_STORAGE_SIDE
            assert plan.compact_cells == width * height
            assert plan.padding_cells == plan.storage_cells - plan.compact_cells
            max_padding = max(max_padding, plan.padding_cells)
            stride_counts[plan.stride] = stride_counts.get(plan.stride, 0) + 1
            checked += 1
    assert checked == 256 * 256
    return {
        "combinations": checked,
        "stride_buckets": len(stride_counts),
        "max_padding_cells": max_padding,
    }

# Runtime-only patches for the exact 1.0.2.2818 x86 executable above.
# Each patch is (RVA, original bytes, patched bytes, description).
PATCHES: list[tuple[int, bytes, bytes, str]] = []

def add_push_patch(va: int, old_size: int, new_size: int, description: str) -> None:
    PATCHES.append((
        va - 0x400000,
        b"\x68" + struct.pack("<I", old_size),
        b"\x68" + struct.pack("<I", new_size),
        description,
    ))

def add_cmp_patch(va: int, old_size: int, new_size: int, description: str) -> None:
    PATCHES.append((
        va - 0x400000,
        b"\x3D" + struct.pack("<I", old_size),
        b"\x3D" + struct.pack("<I", new_size),
        description,
    ))


def add_raw_patch(va: int, original: bytes, patched: bytes, description: str) -> None:
    if len(original) != len(patched):
        raise ValueError(f"Raw patch length mismatch for {description}")
    PATCHES.append((va - 0x400000, original, patched, description))

# PUD layer parser hard limits: 128*128*2 (0x8000) -> 256*256*2 (0x20000).
add_cmp_patch(0x004D20B6, 0x8000, 0x20000, "MTXM parser limit")
add_cmp_patch(0x004D20E6, 0x8000, 0x20000, "SQM parser limit")
add_cmp_patch(0x004D21D6, 0x8000, 0x20000, "REGM parser limit")

# Per-tile allocations in the scenario initialization path. 256x256 has four
# times the cells of 128x128, so each fixed map buffer must grow by 4x.
for va, old, new, name in [
    (0x004C6149, 0x10000, 0x40000, "map buffer A allocation"),
    (0x004C6170, 0x08000, 0x20000, "MTXM allocation"),
    (0x004C618B, 0x10000, 0x40000, "map buffer B allocation"),
    (0x004C61A6, 0x10000, 0x40000, "map buffer C allocation"),
    (0x004C61C1, 0x04000, 0x10000, "map byte buffer A allocation"),
    (0x004C61DC, 0x04000, 0x10000, "map byte buffer B allocation"),
    (0x004C61F7, 0x04000, 0x10000, "map byte buffer C allocation"),
    (0x004C6212, 0x04000, 0x10000, "map byte buffer D allocation"),
    (0x004C622D, 0x08000, 0x20000, "map word buffer allocation"),
    (0x004C6248, 0x08000, 0x20000, "SQM allocation"),
    (0x004C6263, 0x40000, 0x100000, "REGM/workspace allocation"),
]:
    add_push_patch(va, old, new, name)

# Scenario initialization copy/clear lengths.
for va, old, new, name in [
    (0x004C6451, 0x08000, 0x20000, "REGM initial copy length"),
    (0x004C6462, 0x08000, 0x20000, "MTXM initial copy length"),
    (0x004C6473, 0x08000, 0x20000, "SQM initial copy length"),
    (0x004C6484, 0x10000, 0x40000, "map buffer B copy length"),
    (0x004C6495, 0x10000, 0x40000, "map buffer C copy length"),
    (0x004C64C1, 0x04000, 0x10000, "map byte buffer A copy length"),
    (0x004C64D2, 0x04000, 0x10000, "map byte buffer B copy length"),
    (0x004C64E3, 0x04000, 0x10000, "map byte buffer C copy length"),
    (0x004C64FA, 0x10000, 0x40000, "map buffer B clear length"),
    (0x004C650C, 0x10000, 0x40000, "map buffer C clear length"),
    (0x004C651E, 0x04000, 0x10000, "map byte buffer B clear length"),
    (0x004C6548, 0x04000, 0x10000, "map byte buffer D clear length"),
    (0x004AFCD0, 0x04000, 0x10000, "normal-mode byte buffer clear A"),
    (0x004AFCE2, 0x04000, 0x10000, "normal-mode byte buffer clear B"),
    (0x004AFE10, 0x04000, 0x10000, "alternate-mode byte buffer clear A"),
    (0x004AFE22, 0x04000, 0x10000, "alternate-mode byte buffer clear B"),
]:
    add_push_patch(va, old, new, name)

# Autosave/save-state serialization uses fixed temporary buffers and fixed
# transfer sizes for the map layers. Crash 17 reached this path after the
# extended scenario and navigation data had initialized successfully. The
# pointer-grid conversion at 0x004E0370 iterates map_width * map_width DWORDs,
# so its temporary buffer must hold 0x40000 bytes for a 256x256 square map.
for va, old, new, name in [
    (0x004E0FE6, 0x08000, 0x20000, "autosave REGM temporary allocation"),
    (0x004E0FF0, 0x08000, 0x20000, "autosave REGM copy length"),
    (0x004E1004, 0x08000, 0x20000, "autosave REGM write length"),
    (0x004E1038, 0x08000, 0x20000, "autosave MTXM temporary allocation"),
    (0x004E1042, 0x08000, 0x20000, "autosave MTXM copy length"),
    (0x004E1056, 0x08000, 0x20000, "autosave MTXM write length"),
    (0x004E108A, 0x08000, 0x20000, "autosave SQM temporary allocation"),
    (0x004E1094, 0x08000, 0x20000, "autosave SQM copy length"),
    (0x004E10A8, 0x08000, 0x20000, "autosave SQM write length"),
    (0x004E10DC, 0x10000, 0x40000, "autosave pointer-grid temporary allocation"),
    (0x004E10E6, 0x10000, 0x40000, "autosave pointer-grid A copy length"),
    (0x004E1100, 0x10000, 0x40000, "autosave pointer-grid A write length"),
    (0x004E1116, 0x10000, 0x40000, "autosave pointer-grid B copy length"),
    (0x004E112E, 0x10000, 0x40000, "autosave pointer-grid B write length"),
    (0x004E1157, 0x04000, 0x10000, "autosave map byte buffer A write length"),
    (0x004E1173, 0x04000, 0x10000, "autosave map byte buffer B write length"),
    (0x004E118F, 0x04000, 0x10000, "autosave map byte buffer C write length"),
]:
    add_push_patch(va, old, new, name)

# Minimap/fog refresh paths still copied or cleared only the stock 128*128
# byte range. At 256x256 that leaves the lower three quarters stale, causing
# revealed fog to appear at the wrong minimap position.
for va, name in [
    (0x004D397D, "minimap fog-state refresh copy length"),
    (0x004D39D9, "minimap fog-state reset length"),
    (0x004D39EB, "minimap explored-mask reset length"),
]:
    add_push_patch(va, 0x04000, 0x10000, name)

# The stock minimap initializer has explicit branches for 32, 64 and 96,
# then treats every other map as 128. Its final 26-byte branch can support
# both 128 and 256 without a code cave: map_width >> 7 yields the required
# divisor (1 or 2), and divisor-1 is the viewport rounding adjustment.
# This fixes world->minimap positions, minimap clicks and the camera box.
add_raw_patch(
    0x004D416B,
    bytes.fromhex(
        "b8 01 00 00 00 66 a3 50 26 92 00 33 c0 "
        "66 a3 54 26 92 00 66 a3 58 26 92 00 c3"
    ),
    bytes.fromhex(
        "66 c1 e8 07 66 a3 50 26 92 00 48 "
        "66 a3 54 26 92 00 33 c0 "
        "66 a3 58 26 92 00 c3"
    ),
    "128/256 minimap coordinate scale",
)

# 8x8 navigation-region records. The stock 0x4200-byte static array stores
# exactly 16*16 records of 0x42 bytes. A 256x256 map has 32*32 records.
add_push_patch(0x004CBD14, 0x04200, 0x10800, "navigation block buffer clear length")

# The stock navigation array is embedded in the executable data section at
# preferred VA 0x0091D960. It is immediately followed by its loop-bound bytes,
# so an extended map overwrites those bounds after record 255. We allocate a
# 0x10800-byte process buffer and redirect every absolute base reference to it.
RVA_NAV_BLOCK_BUFFER = 0x51D960
NAV_BLOCK_BUFFER_STOCK_SIZE = 0x04200
NAV_BLOCK_BUFFER_EXTENDED_SIZE = 0x10800
NAV_BLOCK_BUFFER_XREF_RVAS = [
    0x0CB7D5,
    0x0CBBC6,
    0x0CBD1C,
    0x0CBD34,
    0x0CBEC5,
    0x0CC6A6,
    0x0CC6AD,
]

# Map globals used for live status display.
RVA_MAP_WIDTH = 0x518D10
RVA_MTXM_PTR = 0x51AD68
RVA_SQM_PTR = 0x51AD58
RVA_REGM_PTR = 0x51AD7C
# Fog/visibility and traversal buffers. The engine still stores rectangular
# maps in a safe square backing grid, so padding cells must remain permanently
# outside-map. H_ALL (0x10) makes both the renderer and minimap draw black;
# 0xFF keeps all-player visibility and traversal state blocked.
RVA_GRAY_MASK_PTR = 0x51AD5C
RVA_LOCAL_MASK_PTR = 0x51AD60
RVA_ALL_PLAYER_MASK_PTR = 0x51AD64
RVA_TRAVERSAL_MAP_PTR = 0x51AD74
H_ALL = 0x10
NO_FACE = 0xFF
RVA_MINIMAP_REDRAW_TIMER = 0x52264C
RVA_MINIMAP_DIVISOR = 0x522650
RVA_MINIMAP_DIV_ADJUST = 0x522654
RVA_MINIMAP_SHIFT = 0x522658

# world-to-minimap formula: (tile << shift) / divisor. The static code patch
# directly covers 128 and 256. Monitoring also supplies exact ratios for the
# extended intermediate sizes exposed by PUD Studio.
MINIMAP_SCALE_BY_SIZE: dict[int, tuple[int, int, int]] = {
    32: (1, 0, 2),
    64: (1, 0, 1),
    96: (3, 3, 2),
    128: (1, 0, 0),
    160: (5, 4, 2),
    192: (3, 2, 1),
    224: (7, 6, 2),
    256: (2, 1, 0),
}


# Copy/clear/write lengths must follow the loaded map size. Earlier lab
# releases forced these sites to their 256x256 maxima, which made a later
# stock-size map read beyond its smaller parsed source buffers. Version 0.5
# installs a tiny in-process hook that updates these immediates before every
# scenario initialization:
#   width <= 128: preserve Warcraft II's stock 128x128 working lengths
#   width > 128:  use width*width cells (1, 2, or 4 bytes per cell)
DYNAMIC_BYTE_SIZE_RVAS = [
    0x0C64C1, 0x0C64D2, 0x0C64E3, 0x0C651E, 0x0C6548,
    0x0AFCD0, 0x0AFCE2, 0x0AFE10, 0x0AFE22,
    0x0E1157, 0x0E1173, 0x0E118F,
    0x0D397D, 0x0D39D9, 0x0D39EB,
]
# All byte-size sites remain ordinary PUSH immediates. The parser-tail rectangle
# hooks expand MTXM/SQM/REGM before scenario initialization, so no scenario
# instruction is replaced by a byte-layer expansion hook.
DYNAMIC_BYTE_HOOK_RVAS = list(DYNAMIC_BYTE_SIZE_RVAS)
DYNAMIC_WORD_SIZE_RVAS = [
    0x0C6451, 0x0C6462, 0x0C6473,
    0x0E0FF0, 0x0E1004, 0x0E1042, 0x0E1056, 0x0E1094, 0x0E10A8,
]
DYNAMIC_DWORD_SIZE_RVAS = [
    0x0C6484, 0x0C6495, 0x0C64FA, 0x0C650C,
    0x0E10E6, 0x0E1100, 0x0E1116, 0x0E112E,
]
DYNAMIC_SIZE_RVAS = set(
    DYNAMIC_BYTE_SIZE_RVAS + DYNAMIC_WORD_SIZE_RVAS + DYNAMIC_DWORD_SIZE_RVAS
)

RVA_DYNAMIC_SIZE_HOOK = 0x0C6448
DYNAMIC_SIZE_HOOK_ORIGINAL = bytes.fromhex("85 ff 0f 84 aa 00 00 00")
DYNAMIC_SIZE_HOOK_MARKER = b"W2EMDYN0"
DYNAMIC_SIZE_CAVE_SIZE = 0x1000
PAGE_EXECUTE_READ = 0x20

RVA_MINIMAP_SCALE_CODE = 0x0D416B

# Version 0.9.0 all-size raw-DIM loader. The DIM hook captures both
# authored dimensions and selects a safe square storage stride. MTXM, SQM and
# REGM are expanded immediately after their exact PUD chunk copies, before any
# engine routine can reinterpret compact rows with the square stride.
RVA_DIM_HANDLER = 0x0D1FE0
DIM_HOOK_ORIGINAL = bytes.fromhex("55 8b ec 83 7d 08 04 75")
RVA_RECT_MTXM_TAIL = 0x0D20C9
RVA_RECT_SQM_TAIL = 0x0D20F9
RVA_RECT_REGM_TAIL = 0x0D21E9
RECT_LAYER_TAIL_ORIGINAL = bytes.fromhex("83 c4 08 84 c0 0f 95 c0 5d c3")
RECT_LAYER_HOOK_LENGTH = 10
AUTO_RECT_CAVE_SIZE = 0x4000
AUTO_RECT_MARKER = b"W2EMAUT11"
AUTO_RECT_TEMPLATE_B64 = "nGAPtwUzMzMzPYAAAAB3B7gAQAAA6wMPr8CjRERERInDAduJ2QHJowEAAECjAgAAQKMDAABAowQAAECjBQAAQKMGAABAowcAAECjCAAAQKMJAABAowoAAECjCwAAQKMMAABAow0AAECjDgAAQIkdAQAAUIkdAgAAUIkdAwAAUIkdBAAAUIkdBQAAUIkdBgAAUIkdBwAAUIkdCAAAUIkdCQAAUIkNAQAAYIkNAgAAYIkNAwAAYIkNBAAAYIkNBQAAYIkNBgAAYIkNBwAAYIkNCAAAYKMPAABAMcAPomGdhf90Bmh3d3d3w2iIiIiIw5CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQVYnlg30IBHV1agRomZmZmbiqqqqq/9CDxAiEwHRgD7cFmZmZmQ+3Dbu7u7uFwHROhcl0Sj0AAQAAd0OB+QABAAB3OznIcwKJyIP4IHMFuCAAAACDwB+D4OBmozMzMzNmo8zMzMzGBREREREBxgUSEhISAMYFIiIiIgCwAV3DMMBdw5CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQg8QIUITAdFmcYIA9EREREQF1TPYFEhISEgF1Q4s93d3d3YX/dDkPtwWZmZmZD7cdu7u7uw+3FTMzMzNqAWoAUlNQV+h4AwAAgA0SEhISAYA9EhISEgd1B8YFIiIiIgFhnViEwA+VwF3DkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCDxAhQhMB0XJxggD0RERERAXVP9gUSEhISAnVGiz3u7u7uhf90PA+3BZmZmZkPtx27u7u7D7cVMzMzM2oAaIEAAABSU1BX6PUCAACADRISEhICgD0SEhISB3UHxgUiIiIiAWGdWITAD5XAXcOQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQg8QIUITAdFycYIA9EREREQF1T/YFEhISEgR1Ros9/////4X/dDwPtwWZmZmZD7cdu7u7uw+3FTMzMzNqAGj9/wAAUlNQV+h1AAAAgA0SEhISBIA9EhISEgd1B8YFIiIiIgFhnViEwA+VwF3DkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQVYnlU1ZX/ItVCIXSD4SiAAAAi10QhdsPhJcAAABLidgPr0UM0eCNNAKJ2A+vRRTR4I08AotNDIXJdA2NdE7+jXxP/v1m86X8idgPr0UU0eCNPAKLTRQrTQx+HIN9HAF1CotFDEhmiwRH6wOLRRiLdQyNPHdm86tLeaSLXRA7XRRzMonYD69FFNHgjTwCg30cAXUVi0UQSA+vRRTR4I00AotNFGbzpesJi0UYi00UZvOrQ+vJ/F9eW4nsXcIYAJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQVYnlU1ZX/ItVCIXSD4STAAAAi10QhdsPhIgAAABLidgPr0UMjTQCidgPr0UUjTwCi00Mhcl0DI10Dv+NfA///fOk/InYD69FFI08AotNFCtNDH4ag30cAXUJi0UMSIoEB+sDi0UYi3UMjTw386pLea2LXRA7XRRzLInYD69FFI08AoN9HAF1EotFEEgPr0UUjTQCi00U86TrCItFGItNFPOqQ+vP/F9eW4nsXcIYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABXMkVNQVVUMTE="
AUTO_RECT_SCENARIO_ENTRY = 0x000
AUTO_RECT_DIM_ENTRY = 0x180
AUTO_RECT_MTXM_ENTRY = 0x240
AUTO_RECT_SQM_ENTRY = 0x2C0
AUTO_RECT_REGM_ENTRY = 0x540
AUTO_RECT_LOGICAL_WIDTH = 0x900
AUTO_RECT_LOGICAL_HEIGHT = 0x902
AUTO_RECT_STORAGE_SIDE = 0x904
AUTO_RECT_ACTIVE_FLAG = 0x906
AUTO_RECT_LAYER_MASK = 0x907
AUTO_RECT_EXPANDED_FLAG = 0x908
AUTO_RECT_BYTE_SIZE = 0x90A
AUTO_RECT_MARKER_OFFSET = 0x90E


# 0.9.3 minimap-only correction. This deliberately leaves every 0.9.0 world,
# fog, AI, pathing, autosave, navigation, and 256x256 patch unchanged.
# Only true rectangles receive dedicated native-side minimap raster buffers and
# independent X/Y transforms. Every square map bypasses all five new hooks.
RECT_MINIMAP_CAVE_SIZE = 0x1000
RECT_MINIMAP_BUFFER_SIZE = 0x10000
RECT_MINIMAP_MARKER = b"W2EMMINI3"
RECT_MINIMAP_TEMPLATE_B64 = "gD0zMzMzAA+EYQEAAIA9paWlpQAPhFQBAAAPtwURERERZjsFIiIiIg+EQAEAAA+/RhiFwHkCMcBpwIAAAACZD7cNEREREff5g8AYg/gYfQW4GAAAAD2XAAAAfgW4lwAAAIlF+A+/RhqFwHkCMcBpwIAAAACZD7cNIiIiIvf5g8ACg/gCfQW4AgAAAD2BAAAAfgW4gQAAAIlF9A+2XicPtwSdRERERGnAgAAAAA+3DREREREPtxUiIiIiOdEPQsoByEgx0vfxg/gCcwW4AgAAAIP4BnYFuAYAAAC5mAAAACtN+DnIfgKJyIP4AX0FuAEAAACJRfwPtwSdRkRERGnAgAAAAA+3DREREREPtxUiIiIiOdEPQsoByEgx0vfxg/gCcwW4AgAAAIP4BnYFuAYAAAC5ggAAACtN9DnIfgKJyIP4AX0FuAEAAACJRfAPtkULUP918P91/P919P91+Liqqqqq/9CDxBRfXluJ7F3DD7cN7u7u7mjv7+/vw4A9MzMzMwAPhJQAAACAPaWlpaUAD4SHAAAAD7cFEREREWY7BSIiIiJ0d4tEJAQPvwiD6Rh5AjHJg/l/fgW5fwAAAInIacCAAAAAD7cVEREREQ+vwsHoDjnQcgNKidCLVCQEZokCi0QkCA+/CIPpGnkCMcmD+X9+Bbl/AAAAichpwIAAAAAPtxUiIiIiD6/CwegOOdByA0qJ0ItUJAhmiQLDVYnlU1Zo8PDw8MOAPTMzMzMAD4TdAAAAgD2lpaWlAA+E0AAAAA+3BRERERFmOwUiIiIiD4S8AAAAWw+2BVVVVVVQD7cFwsLCwmvABA+3DSIiIiIByEgx0vfxg/gBcwW4AQAAAD2AAAAAdgW4gAAAAFAPtwXBwcHBa8AED7cNEREREQHISDHS9/GD+AFzBbgBAAAAPYAAAAB2BbiAAAAAUKF3d3d3hcB5AjHAa8AEMdIPtw0iIiIi9/GD+H92Bbh/AAAAUKFmZmZmhcB5AjHAa8AEMdIPtw0RERER9/GD+H92Bbh/AAAAULi7u7u7/9CDxBRfXsMPtgVVVVVVaPHx8fHDgD2lpaWlAHRjWKOmpqamYKGQkJCQo7GxsbGhlJSUlKOysrKyoZiYmJijs7Ozsw+3BZycnJxmo7S0tLShoaGhoaOQkJCQoaKioqKjlJSUlKGjo6Ojo5iYmJgPtwWkpKSkZqOcnJycYWjR0dHRVYnlav9o0tLS0sNgobGxsbGjkJCQkKGysrKyo5SUlJShs7Ozs6OYmJiYD7cFtLS0tGajnJycnGH/JaampqaAPaWlpaUAdGNYo6enp6dgoZCQkJCjxcXFxaGUlJSUo8bGxsahmJiYmKPHx8fHD7cFnJycnGajyMjIyKGhoaGho5CQkJChoqKioqOUlJSUoaOjo6OjmJiYmA+3BaSkpKRmo5ycnJxhaNPT09NVieVRZosVnJycnGjU1NTUw2ChxcXFxaOQkJCQocbGxsajlJSUlKHHx8fHo5iYmJgPtwXIyMjIZqOcnJycYf8lp6enp1cyRU1NSU5JM5BmkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
RECT_MINIMAP_ENTRY_OFFSETS = {
    "dot_hook": 0x000,
    "click_hook": 0x17B,
    "camera_hook": 0x227,
    "fog_entry": 0x31E,
    "fog_restore": 0x395,
    "terrain_entry": 0x3C8,
    "terrain_restore": 0x445,
    "marker": 0x478,
    "state": 0x484,
}
RECT_MINIMAP_STATE_TERRAIN_PTR = 0x484
RECT_MINIMAP_STATE_GRAY_PTR = 0x488
RECT_MINIMAP_STATE_LOCAL_PTR = 0x48C
RECT_MINIMAP_STATE_SIDE = 0x490
RECT_MINIMAP_STATE_READY = 0x492
RECT_MINIMAP_STATE_FOG_RETURN = 0x494
RECT_MINIMAP_STATE_TERRAIN_RETURN = 0x498
RECT_MINIMAP_STATE_FOG_SAVE_TERRAIN = 0x49C
RECT_MINIMAP_STATE_FOG_SAVE_GRAY = 0x4A0
RECT_MINIMAP_STATE_FOG_SAVE_LOCAL = 0x4A4
RECT_MINIMAP_STATE_FOG_SAVE_SIDE = 0x4A8
RECT_MINIMAP_STATE_TERRAIN_SAVE_TERRAIN = 0x4AC
RECT_MINIMAP_STATE_TERRAIN_SAVE_GRAY = 0x4B0
RECT_MINIMAP_STATE_TERRAIN_SAVE_LOCAL = 0x4B4
RECT_MINIMAP_STATE_TERRAIN_SAVE_SIDE = 0x4B8
RECT_MINIMAP_HOOK_SITES = [
    (0x0D3DE6, bytes.fromhex("0f b7 0d 58 26 92 00"), "dot_hook", 7,
     "rectangular minimap unit/building dots"),
    (0x0D3ED0, bytes.fromhex("55 8b ec 53 56"), "click_hook", 5,
     "rectangular minimap clicks"),
    (0x0D425C, bytes.fromhex("0f b6 05 98 b3 8c 00"), "camera_hook", 7,
     "rectangular minimap camera rectangle"),
    (0x10DCB0, bytes.fromhex("55 8b ec 6a ff"), "fog_entry", 5,
     "scoped rectangular minimap fog-buffer swap"),
    (0x10DE20, bytes.fromhex("55 8b ec 51 66 8b 15 9c 95 8c 00"), "terrain_entry", 11,
     "scoped rectangular minimap terrain-buffer swap"),
]
RVA_MINIMAP_TERRAIN_PTR = 0x4C9590
RVA_MINIMAP_GRAY_PTR = 0x4C9594
RVA_MINIMAP_LOCAL_PTR = 0x4C9598
RVA_MINIMAP_SIDE = 0x4C959C
RVA_UNIT_DIM_TABLE = 0x517AD0
RVA_MINIMAP_CAMERA_COLOR = 0x4CB398
RVA_MINIMAP_DRAW_FILLED = 0x10E440
RVA_MINIMAP_DRAW_OUTLINE = 0x10E4A0
RECT_MINIMAP_TERRAIN_OFFSET = 0x0000
RECT_MINIMAP_GRAY_OFFSET = 0x8000
RECT_MINIMAP_LOCAL_OFFSET = 0xC000
RECT_MINIMAP_SIDE = 128


def rect_minimap_raster_side(storage_side: int) -> int:
    """Choose a native Warcraft minimap side for rectangular-only rasters.

    Small/normal rectangles retain the proven stock side (32/64/96/128) and
    Warcraft performs its own final stretch to the 128-pixel panel. Larger
    rectangle backing grids cap at 128 because the dedicated minimap buffers
    are 128x128. Square maps never use this path.
    """
    if not 1 <= storage_side <= 256:
        fail(f"Invalid rectangular minimap storage side {storage_side}.")
    if storage_side <= 32:
        return 32
    if storage_side <= 64:
        return 64
    if storage_side <= 96:
        return 96
    return 128

RVA_SCROLL_PIXEL_X = 0x51AD80
RVA_SCROLL_PIXEL_Y = 0x51AD84
RVA_VIEWPORT_PIXEL_WIDTH = 0x51CB08
RVA_VIEWPORT_PIXEL_HEIGHT = 0x51CB0C
TILE_PIXELS = 32



# 0.9.5 native legacy-style rectangular camera bounds.
#
# The legacy source computes:
#   gwMapMtxRgt = gwMapMtxWdt - gwGAMEMAP_MTX_WDT
#   gwMapMtxBtm = gwMapMtxHgt - gwGAMEMAP_MTX_HGT
# and clamps the camera against those independent values. The 0.9 loader keeps
# a square backing stride, so the stock remaster clamp sees 96x96 for a 32x96
# map and permits the viewport to enter columns 32..95. These four hooks change
# only camera boundary calculations. Row addressing and every stable 0.9.0
# gameplay/256x256 patch remain untouched.
RECT_SCROLL_CAVE_SIZE = 0x200
RECT_SCROLL_MARKER = b"W2EMSCR5"
RECT_SCROLL_ENTRY_OFFSETS = {
    "clamp_width": 0x00,
    "clamp_height": 0x20,
    "setpos_width": 0x50,
    "setpos_height": 0x70,
    "marker": 0xA0,
}
RECT_SCROLL_HOOK_SITES = [
    (0x0AFD00, "clamp_width", "native camera clamp logical width"),
    (0x0AFD3D, "clamp_height", "native camera clamp logical height"),
    (0x0AFD73, "setpos_width", "native set-position logical width"),
    (0x0AFDC0, "setpos_height", "native set-position logical height"),
]


def _rect_scroll_original(base: int, rva: int) -> bytes:
    if rva == 0x0AFD00:
        return b"\x0F\xB7\x0D" + struct.pack("<I", base + 0x518D10)
    if rva == 0x0AFD3D:
        return b"\x0F\xB7\x05" + struct.pack("<I", base + RVA_VIEWPORT_PIXEL_HEIGHT)
    if rva == 0x0AFD73:
        return b"\x0F\xB7\x15" + struct.pack("<I", base + 0x518D10)
    if rva == 0x0AFDC0:
        return b"\x0F\xB7\x3D" + struct.pack("<I", base + RVA_VIEWPORT_PIXEL_HEIGHT)
    raise ValueError(f"Unknown native scroll hook RVA 0x{rva:06X}")


def _rect_scroll_load_with_fallback(opcode: bytes, logical: int, stock: int, return_to: int) -> bytes:
    # movzx reg, word ptr [logical]
    # test reg, reg
    # jnz have_value
    # movzx reg, word ptr [stock]
    # have_value: push return; ret
    if opcode == b"\x0F\xB7\x0D":      # ECX
        test = b"\x85\xC9"
    elif opcode == b"\x0F\xB7\x15":    # EDX
        test = b"\x85\xD2"
    else:
        raise ValueError("Unsupported scroll fallback opcode")
    return (
        opcode + struct.pack("<I", logical)
        + test
        + b"\x75\x07"
        + opcode + struct.pack("<I", stock)
        + b"\x68" + struct.pack("<I", return_to)
        + b"\xC3"
    )


def build_rect_scroll_cave(base: int, auto_cave: int, cave: int) -> bytes:
    payload = bytearray(b"\x90" * RECT_SCROLL_CAVE_SIZE)
    logical_w = auto_cave + AUTO_RECT_LOGICAL_WIDTH
    logical_h = auto_cave + AUTO_RECT_LOGICAL_HEIGHT
    stock_side = base + 0x518D10
    viewport_h = base + RVA_VIEWPORT_PIXEL_HEIGHT

    width1 = _rect_scroll_load_with_fallback(
        b"\x0F\xB7\x0D", logical_w, stock_side, base + 0x0AFD07
    )
    payload[0x00:0x00 + len(width1)] = width1

    # Reload independent height in pixels before the vertical half of the
    # ordinary clamp. The displaced instruction loads viewport height into EAX.
    height1 = (
        b"\x0F\xB7\x0D" + struct.pack("<I", logical_h)
        + b"\x85\xC9\x75\x07"
        + b"\x0F\xB7\x0D" + struct.pack("<I", stock_side)
        + b"\xC1\xE1\x05"
        + b"\x0F\xB7\x05" + struct.pack("<I", viewport_h)
        + b"\x68" + struct.pack("<I", base + 0x0AFD44)
        + b"\xC3"
    )
    payload[0x20:0x20 + len(height1)] = height1

    width2 = _rect_scroll_load_with_fallback(
        b"\x0F\xB7\x15", logical_w, stock_side, base + 0x0AFD7A
    )
    payload[0x50:0x50 + len(width2)] = width2

    # Reload independent height in pixels before the vertical half of
    # cell_set_pos. The displaced instruction loads viewport height into EDI.
    height2 = (
        b"\x0F\xB7\x15" + struct.pack("<I", logical_h)
        + b"\x85\xD2\x75\x07"
        + b"\x0F\xB7\x15" + struct.pack("<I", stock_side)
        + b"\xC1\xE2\x05"
        + b"\x0F\xB7\x3D" + struct.pack("<I", viewport_h)
        + b"\x68" + struct.pack("<I", base + 0x0AFDC7)
        + b"\xC3"
    )
    payload[0x70:0x70 + len(height2)] = height2
    payload[RECT_SCROLL_ENTRY_OFFSETS["marker"]:RECT_SCROLL_ENTRY_OFFSETS["marker"] + len(RECT_SCROLL_MARKER)] = RECT_SCROLL_MARKER
    return bytes(payload)


def _decode_rect_scroll_cave(base: int, rva: int, payload: bytes, entry: str) -> int:
    if len(payload) < 5 or payload[0] != 0xE9:
        fail(f"Code at RVA 0x{rva:06X} is not a native scroll JMP.")
    target = base + rva + 5 + struct.unpack("<i", payload[1:5])[0]
    return target - RECT_SCROLL_ENTRY_OFFSETS[entry]


def install_or_restore_rect_scroll_hooks(
    kernel32, process, base: int, auto_cave: int | None,
    restore: bool, dry_run: bool,
) -> int | None:
    originals = {rva: _rect_scroll_original(base, rva) for rva, _entry, _desc in RECT_SCROLL_HOOK_SITES}
    current = {rva: read_memory(kernel32, process, base + rva, 7) for rva, _entry, _desc in RECT_SCROLL_HOOK_SITES}
    stock = all(current[rva] == originals[rva] for rva in originals)

    def discover() -> int:
        caves = []
        for rva, entry, _desc in RECT_SCROLL_HOOK_SITES:
            payload = current[rva]
            if payload[:1] == b"\xE9":
                caves.append(_decode_rect_scroll_cave(base, rva, payload, entry))
        if not caves or len(set(caves)) != 1:
            fail("Native rectangle scroll hooks are partially installed; restart Warcraft II.")
        return caves[0]

    if restore:
        if stock:
            print("[already restored] native legacy-style rectangle camera bounds")
            return None
        cave = discover()
        marker = read_memory(kernel32, process, cave + RECT_SCROLL_ENTRY_OFFSETS["marker"], len(RECT_SCROLL_MARKER))
        if marker != RECT_SCROLL_MARKER:
            fail("Installed camera-bound hooks do not belong to Lab 0.9.5.")
        print(f"[{'would restore' if dry_run else 'restore'}] native legacy-style rectangle camera bounds")
        if not dry_run:
            for rva, original in originals.items():
                write_code(kernel32, process, base + rva, original)
        return cave

    if auto_cave is None:
        if dry_run:
            print("[would install] 4 native legacy-style rectangle camera-bound hooks")
            return None
        fail("Rectangle loader cave is unavailable for native camera bounds.")

    if stock:
        if dry_run:
            print("[would install] 4 native legacy-style rectangle camera-bound hooks")
            return None
        pointer = kernel32.VirtualAllocEx(
            process, None, RECT_SCROLL_CAVE_SIZE,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE,
        )
        cave = ctypes.cast(pointer, ctypes.c_void_p).value if pointer else 0
        if not cave:
            fail(
                "VirtualAllocEx failed for native rectangle camera bounds: "
                f"Win32 error {ctypes.get_last_error()}"
            )
        cave = int(cave)
        write_data(kernel32, process, cave, build_rect_scroll_cave(base, int(auto_cave), cave))
        for rva, entry, _desc in RECT_SCROLL_HOOK_SITES:
            write_code(kernel32, process, base + rva, _mini_jump(base, rva, cave + RECT_SCROLL_ENTRY_OFFSETS[entry], 7))
        print(
            f"[allocated] native legacy-style camera-bound hook 0x{cave:08X}; "
            "logical width/height minus the live viewport"
        )
        return cave

    cave = discover()
    marker = read_memory(kernel32, process, cave + RECT_SCROLL_ENTRY_OFFSETS["marker"], len(RECT_SCROLL_MARKER))
    if marker != RECT_SCROLL_MARKER:
        fail("A different camera-bound hook is installed; restart Warcraft II.")
    for rva, entry, desc in RECT_SCROLL_HOOK_SITES:
        payload = current[rva]
        expected = cave + RECT_SCROLL_ENTRY_OFFSETS[entry]
        if payload[:1] != b"\xE9" or _mini_decode_target(base, rva, payload) != expected:
            fail(f"Native camera-bound hook mismatch at RVA 0x{rva:06X} ({desc}).")
    print(f"[already patched] native legacy-style rectangle camera bounds -> 0x{cave:08X}")
    return cave


def build_runtime_minimap_scale_patch(base: int) -> tuple[bytes, bytes]:
    """Build the live-process bytes for the ASLR-relocated minimap branch."""
    divisor = struct.pack("<I", base + RVA_MINIMAP_DIVISOR)
    adjustment = struct.pack("<I", base + RVA_MINIMAP_DIV_ADJUST)
    shift = struct.pack("<I", base + RVA_MINIMAP_SHIFT)

    original = (
        b"\xB8\x01\x00\x00\x00"
        + b"\x66\xA3" + divisor
        + b"\x33\xC0"
        + b"\x66\xA3" + adjustment
        + b"\x66\xA3" + shift
        + b"\xC3"
    )
    patched = (
        b"\x66\xC1\xE8\x07"
        + b"\x66\xA3" + divisor
        + b"\x48"
        + b"\x66\xA3" + adjustment
        + b"\x33\xC0"
        + b"\x66\xA3" + shift
        + b"\xC3"
    )
    if len(original) != 26 or len(patched) != 26:
        raise AssertionError("Minimap runtime patch must remain exactly 26 bytes")
    return original, patched

def resolve_runtime_patch(
    base: int, rva: int, original: bytes, patched: bytes
) -> tuple[bytes, bytes]:
    # Most patches contain only constants and are unchanged by ASLR. The
    # minimap branch embeds three absolute addresses, so Windows relocates
    # those operands when the module is loaded at a non-preferred base.
    if rva == RVA_MINIMAP_SCALE_CODE:
        return build_runtime_minimap_scale_patch(base)
    return original, patched

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_SYNCHRONIZE = 0x00100000
PROCESS_ACCESS = (
    PROCESS_QUERY_INFORMATION
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_SYNCHRONIZE
)
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
WAIT_TIMEOUT = 0x00000102


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", wintypes.WCHAR * 256),
        ("szExePath", wintypes.WCHAR * 260),
    ]


def fail(message: str) -> "NoReturn":
    raise RuntimeError(message)


def parse_pe_identity(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        fail(f"Not a PE executable: {path}")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        fail(f"Invalid PE signature: {path}")
    timestamp = struct.unpack_from("<I", data, pe_off + 8)[0]
    optional_off = pe_off + 24
    image_size = struct.unpack_from("<I", data, optional_off + 56)[0]
    return timestamp, image_size


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def configure_api():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.WriteProcessMemory.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,
        ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    kernel32.VirtualProtectEx.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.VirtualProtectEx.restype = wintypes.BOOL
    kernel32.VirtualAllocEx.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t,
        wintypes.DWORD, wintypes.DWORD,
    ]
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    kernel32.VirtualFreeEx.argtypes = [
        wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD,
    ]
    kernel32.VirtualFreeEx.restype = wintypes.BOOL
    kernel32.FlushInstructionCache.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.c_size_t]
    kernel32.FlushInstructionCache.restype = wintypes.BOOL
    kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def close_handle(kernel32, handle) -> None:
    if handle and handle != INVALID_HANDLE_VALUE:
        kernel32.CloseHandle(handle)


def enum_processes(kernel32) -> list[tuple[int, str]]:
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == INVALID_HANDLE_VALUE:
        fail(f"CreateToolhelp32Snapshot(process) failed: {ctypes.get_last_error()}")
    results: list[tuple[int, str]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            results.append((int(entry.th32ProcessID), entry.szExeFile))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        close_handle(kernel32, snapshot)
    return results


def get_main_module(kernel32, pid: int) -> tuple[int, int, Path]:
    flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    snapshot = kernel32.CreateToolhelp32Snapshot(flags, pid)
    if snapshot == INVALID_HANDLE_VALUE:
        fail(f"Cannot enumerate modules for PID {pid}: Win32 error {ctypes.get_last_error()}")
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            fail(f"Module32FirstW failed for PID {pid}: Win32 error {ctypes.get_last_error()}")
        base = ctypes.cast(entry.modBaseAddr, ctypes.c_void_p).value
        if not base:
            fail("Main module base is null.")
        return int(base), int(entry.modBaseSize), Path(entry.szExePath)
    finally:
        close_handle(kernel32, snapshot)


def find_target(kernel32, requested_pid: int | None) -> tuple[int, int, Path]:
    candidates = []
    for pid, name in enum_processes(kernel32):
        if requested_pid is not None and pid != requested_pid:
            continue
        if requested_pid is None and name.lower() != TARGET_EXE.lower():
            continue
        try:
            base, size, path = get_main_module(kernel32, pid)
        except RuntimeError:
            continue
        candidates.append((pid, base, size, path))
    if not candidates:
        if requested_pid is not None:
            fail(f"PID {requested_pid} was not found or its modules could not be read.")
        fail(f"{TARGET_EXE} is not running. Start the remaster and stop at the main menu.")
    candidates.sort(key=lambda row: row[0], reverse=True)
    if len(candidates) > 1:
        print("Multiple Warcraft II.exe processes found:")
        for pid, base, size, path in candidates:
            print(f"  PID {pid}: base 0x{base:08X}, size 0x{size:X}, {path}")
        print(f"Using newest/highest PID {candidates[0][0]}. Use --pid to choose another.")
    pid, base, _size, path = candidates[0]
    return pid, base, path


def open_target(kernel32, pid: int):
    handle = kernel32.OpenProcess(PROCESS_ACCESS, False, pid)
    if not handle:
        fail(
            f"OpenProcess failed for PID {pid}: Win32 error {ctypes.get_last_error()}. "
            "Run this tool at the same privilege level as the game."
        )
    return handle


def read_memory(kernel32, process, address: int, size: int) -> bytes:
    buffer = (ctypes.c_ubyte * size)()
    transferred = ctypes.c_size_t()
    if not kernel32.ReadProcessMemory(
        process, ctypes.c_void_p(address), buffer, size, ctypes.byref(transferred)
    ) or transferred.value != size:
        fail(f"ReadProcessMemory failed at 0x{address:08X}: Win32 error {ctypes.get_last_error()}")
    return bytes(buffer)


def write_code(kernel32, process, address: int, payload: bytes) -> None:
    old_protect = wintypes.DWORD()
    if not kernel32.VirtualProtectEx(
        process, ctypes.c_void_p(address), len(payload), PAGE_EXECUTE_READWRITE,
        ctypes.byref(old_protect),
    ):
        fail(f"VirtualProtectEx failed at 0x{address:08X}: Win32 error {ctypes.get_last_error()}")
    try:
        source = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
        transferred = ctypes.c_size_t()
        if not kernel32.WriteProcessMemory(
            process, ctypes.c_void_p(address), source, len(payload), ctypes.byref(transferred)
        ) or transferred.value != len(payload):
            fail(f"WriteProcessMemory failed at 0x{address:08X}: Win32 error {ctypes.get_last_error()}")
        kernel32.FlushInstructionCache(process, ctypes.c_void_p(address), len(payload))
    finally:
        ignored = wintypes.DWORD()
        kernel32.VirtualProtectEx(
            process, ctypes.c_void_p(address), len(payload), old_protect.value,
            ctypes.byref(ignored),
        )


def write_data(kernel32, process, address: int, payload: bytes) -> None:
    source = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    transferred = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(
        process, ctypes.c_void_p(address), source, len(payload), ctypes.byref(transferred)
    ) or transferred.value != len(payload):
        fail(f"WriteProcessMemory failed at 0x{address:08X}: Win32 error {ctypes.get_last_error()}")


def allocate_nav_block_buffer(kernel32, process) -> int:
    pointer = kernel32.VirtualAllocEx(
        process,
        None,
        NAV_BLOCK_BUFFER_EXTENDED_SIZE,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE,
    )
    address = ctypes.cast(pointer, ctypes.c_void_p).value if pointer else 0
    if not address:
        fail(
            "VirtualAllocEx failed for the extended navigation buffer: "
            f"Win32 error {ctypes.get_last_error()}"
        )
    return int(address)




def _replace_u32_all(payload: bytearray, sentinel: int, value: int, expected_count: int | None = None) -> None:
    needle = struct.pack("<I", sentinel & 0xFFFFFFFF)
    replacement = struct.pack("<I", value & 0xFFFFFFFF)
    positions: list[int] = []
    start = 0
    while True:
        index = payload.find(needle, start)
        if index < 0:
            break
        positions.append(index)
        start = index + 1
    if expected_count is not None and len(positions) != expected_count:
        fail(
            f"Auto-rectangle cave sentinel 0x{sentinel:08X} appeared "
            f"{len(positions)} times; expected {expected_count}."
        )
    for index in positions:
        payload[index:index + 4] = replacement


def build_auto_rectangle_cave(base: int, cave_address: int) -> bytes:
    payload = bytearray(base64.b64decode(AUTO_RECT_TEMPLATE_B64))
    if len(payload) > AUTO_RECT_CAVE_SIZE:
        fail("Automatic rectangle cave exceeds its allocation.")

    # Cave state addresses.
    _replace_u32_all(payload, 0x99999999, cave_address + AUTO_RECT_LOGICAL_WIDTH)
    _replace_u32_all(payload, 0xBBBBBBBB, cave_address + AUTO_RECT_LOGICAL_HEIGHT)
    _replace_u32_all(payload, 0x33333333, cave_address + AUTO_RECT_STORAGE_SIDE)
    _replace_u32_all(payload, 0x11111111, cave_address + AUTO_RECT_ACTIVE_FLAG)
    _replace_u32_all(payload, 0x12121212, cave_address + AUTO_RECT_LAYER_MASK)
    _replace_u32_all(payload, 0x22222222, cave_address + AUTO_RECT_EXPANDED_FLAG)
    _replace_u32_all(payload, 0x44444444, cave_address + AUTO_RECT_BYTE_SIZE)

    # Engine addresses and return paths.
    _replace_u32_all(payload, 0xAAAAAAAA, base + 0x0D2E30, 1)
    _replace_u32_all(payload, 0xCCCCCCCC, base + RVA_MAP_WIDTH, 1)
    _replace_u32_all(payload, 0xDDDDDDDD, base + RVA_MTXM_PTR, 1)
    _replace_u32_all(payload, 0xEEEEEEEE, base + RVA_SQM_PTR, 1)
    _replace_u32_all(payload, 0xFFFFFFFF, base + RVA_REGM_PTR, 1)
    _replace_u32_all(payload, 0x77777777, base + 0x0C6450, 1)
    _replace_u32_all(payload, 0x88888888, base + 0x0C64FA, 1)

    for index, rva in enumerate(DYNAMIC_BYTE_HOOK_RVAS, 1):
        _replace_u32_all(payload, 0x40000000 + index, base + rva + 1, 1)
    for index, rva in enumerate(DYNAMIC_WORD_SIZE_RVAS, 1):
        _replace_u32_all(payload, 0x50000000 + index, base + rva + 1, 1)
    for index, rva in enumerate(DYNAMIC_DWORD_SIZE_RVAS, 1):
        _replace_u32_all(payload, 0x60000000 + index, base + rva + 1, 1)

    if payload[AUTO_RECT_MARKER_OFFSET:AUTO_RECT_MARKER_OFFSET + len(AUTO_RECT_MARKER)] != AUTO_RECT_MARKER:
        fail("Automatic rectangle cave marker is missing from its template.")
    return bytes(payload)


def hook_jump(base: int, hook_rva: int, target: int, length: int = 8) -> bytes:
    if length < 5:
        fail("Hook overwrite length must be at least five bytes.")
    source_after = base + hook_rva + 5
    displacement = target - source_after
    if not -(1 << 31) <= displacement < (1 << 31):
        fail("Allocated hook cave is outside x86 rel32 range.")
    return b"\xE9" + struct.pack("<i", displacement) + b"\x90" * (length - 5)


def decode_hook_target(base: int, hook_rva: int, payload: bytes) -> int:
    if len(payload) < 5 or payload[0] != 0xE9:
        fail(f"Hook at RVA 0x{hook_rva:06X} is not a recognized JMP.")
    displacement = struct.unpack("<i", payload[1:5])[0]
    return base + hook_rva + 5 + displacement



def install_or_restore_auto_rectangle_hook(
    kernel32,
    process,
    base: int,
    restore: bool,
    dry_run: bool,
) -> int | None:
    hooks = [
        (RVA_DYNAMIC_SIZE_HOOK, DYNAMIC_SIZE_HOOK_ORIGINAL, AUTO_RECT_SCENARIO_ENTRY, 8, "scenario-size"),
        (RVA_DIM_HANDLER, DIM_HOOK_ORIGINAL, AUTO_RECT_DIM_ENTRY, 8, "DIM"),
        (RVA_RECT_MTXM_TAIL, RECT_LAYER_TAIL_ORIGINAL, AUTO_RECT_MTXM_ENTRY, RECT_LAYER_HOOK_LENGTH, "MTXM parser-tail"),
        (RVA_RECT_SQM_TAIL, RECT_LAYER_TAIL_ORIGINAL, AUTO_RECT_SQM_ENTRY, RECT_LAYER_HOOK_LENGTH, "SQM parser-tail"),
        (RVA_RECT_REGM_TAIL, RECT_LAYER_TAIL_ORIGINAL, AUTO_RECT_REGM_ENTRY, RECT_LAYER_HOOK_LENGTH, "REGM parser-tail"),
    ]
    current = {
        rva: read_memory(kernel32, process, base + rva, len(original))
        for rva, original, _entry, _length, _name in hooks
    }
    stock = all(current[rva] == original for rva, original, _entry, _length, _name in hooks)

    if restore:
        if stock:
            print("[already restored] parser-tail raw-rectangle loader")
            return None
        scenario_current = current[RVA_DYNAMIC_SIZE_HOOK]
        cave_address = decode_hook_target(base, RVA_DYNAMIC_SIZE_HOOK, scenario_current)
        for rva, _original, entry, _length, name in hooks:
            actual = decode_hook_target(base, rva, current[rva])
            expected = cave_address + entry
            if actual != expected:
                fail(f"{name} hook does not point to the Lab 0.8.x cave.")
        marker_bytes = read_memory(
            kernel32, process, cave_address + AUTO_RECT_MARKER_OFFSET, len(AUTO_RECT_MARKER)
        )
        if marker_bytes != AUTO_RECT_MARKER:
            fail("Existing all-size hook does not belong to this lab build.")
        print(f"[{'would restore' if dry_run else 'restore'}] parser-tail raw-rectangle loader")
        if not dry_run:
            for rva, original, _entry, _length, _name in hooks:
                write_code(kernel32, process, base + rva, original)
        return cave_address

    if stock:
        if dry_run:
            print("[would install] parser-tail raw rectangular PUD loader")
            return None
        cave_pointer = kernel32.VirtualAllocEx(
            process, None, AUTO_RECT_CAVE_SIZE,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE,
        )
        cave_address = ctypes.cast(cave_pointer, ctypes.c_void_p).value if cave_pointer else 0
        if not cave_address:
            fail(
                "VirtualAllocEx failed for the parser-tail rectangle hook: "
                f"Win32 error {ctypes.get_last_error()}"
            )
        cave_address = int(cave_address)
        cave = build_auto_rectangle_cave(base, cave_address)
        write_data(kernel32, process, cave_address, cave)
        set_dynamic_code_pages(kernel32, process, base, PAGE_EXECUTE_READWRITE)
        for rva, _original, entry, length, _name in hooks:
            write_code(
                kernel32, process, base + rva,
                hook_jump(base, rva, cave_address + entry, length),
            )
        print(
            f"[allocated] parser-tail raw-rectangle hook 0x{cave_address:08X}, "
            f"{len(cave)} bytes; expands MTXM/SQM/REGM immediately after PUD chunk copies"
        )
        return cave_address

    scenario_current = current[RVA_DYNAMIC_SIZE_HOOK]
    if not (scenario_current and scenario_current[0] == 0xE9):
        fail("Only part of the parser-tail rectangle hook is installed. Restart Warcraft II.")
    cave_address = decode_hook_target(base, RVA_DYNAMIC_SIZE_HOOK, scenario_current)
    for rva, _original, entry, _length, name in hooks:
        payload = current[rva]
        if not payload or payload[0] != 0xE9:
            fail(f"The {name} rectangle hook is missing. Restart Warcraft II.")
        if decode_hook_target(base, rva, payload) != cave_address + entry:
            fail(f"The {name} hook belongs to a different Lab build. Restart Warcraft II.")
    marker_bytes = read_memory(
        kernel32, process, cave_address + AUTO_RECT_MARKER_OFFSET, len(AUTO_RECT_MARKER)
    )
    if marker_bytes != AUTO_RECT_MARKER:
        fail("A different or older rectangle hook is already installed. Restart Warcraft II.")
    set_dynamic_code_pages(kernel32, process, base, PAGE_EXECUTE_READWRITE)
    print(f"[already patched] parser-tail raw-rectangle hook -> 0x{cave_address:08X}")
    return cave_address




def _mini_rel32(source_after: int, target: int) -> bytes:
    displacement = target - source_after
    if not -(1 << 31) <= displacement < (1 << 31):
        fail("Rectangular minimap hook target is outside x86 rel32 range.")
    return struct.pack("<i", displacement)


def _mini_jump(base: int, rva: int, target: int, length: int) -> bytes:
    if length < 5:
        fail("Rectangular minimap hook overwrite is shorter than five bytes.")
    return b"\xE9" + _mini_rel32(base + rva + 5, target) + b"\x90" * (length - 5)


def _mini_decode_target(base: int, rva: int, payload: bytes) -> int:
    if len(payload) < 5 or payload[0] != 0xE9:
        fail(f"Code at RVA 0x{rva:06X} is not a rectangular minimap JMP.")
    return base + rva + 5 + struct.unpack("<i", payload[1:5])[0]


def _runtime_mini_original(base: int, original: bytes) -> bytes:
    runtime = bytearray(original)
    preferred_base = 0x00400000
    for rva in (RVA_MINIMAP_SHIFT, RVA_MINIMAP_CAMERA_COLOR, RVA_MINIMAP_SIDE):
        preferred = struct.pack("<I", preferred_base + rva)
        relocated = struct.pack("<I", base + rva)
        start = 0
        while True:
            index = runtime.find(preferred, start)
            if index < 0:
                break
            runtime[index:index + 4] = relocated
            start = index + 4
    return bytes(runtime)




def _replace_u32_nonoverlap(payload: bytearray, sentinel: int, value: int, expected_count: int | None = None) -> None:
    """Replace aligned placeholder occurrences without allowing overlapping matches.

    The old minimap builder advanced one byte after a match. Repeated-byte
    placeholders such as A1 A1 A1 A1 could therefore match both a MOV opcode
    and its immediate, corrupting executable instructions.
    """
    needle = struct.pack("<I", sentinel & 0xFFFFFFFF)
    replacement = struct.pack("<I", value & 0xFFFFFFFF)
    positions: list[int] = []
    start = 0
    while True:
        index = payload.find(needle, start)
        if index < 0:
            break
        positions.append(index)
        start = index + 4
    if expected_count is not None and len(positions) != expected_count:
        fail(
            f"Minimap cave sentinel 0x{sentinel:08X} appeared "
            f"{len(positions)} times; expected {expected_count}."
        )
    for index in positions:
        payload[index:index + 4] = replacement


def _replace_moffs32_load_immediates(
    payload: bytearray, sentinel: int, value: int, expected_count: int,
) -> None:
    """Patch only the four-byte address of `mov eax, moffs32` instructions.

    This is required when the placeholder byte equals opcode A1. It also
    protects A3 A3 A3 A3 immediates followed by an A3 store opcode.
    """
    needle = b"\xA1" + struct.pack("<I", sentinel & 0xFFFFFFFF)
    replacement = struct.pack("<I", value & 0xFFFFFFFF)
    positions: list[int] = []
    start = 0
    while True:
        index = payload.find(needle, start)
        if index < 0:
            break
        positions.append(index)
        start = index + len(needle)
    if len(positions) != expected_count:
        fail(
            f"Minimap MOV placeholder 0x{sentinel:08X} appeared "
            f"{len(positions)} times; expected {expected_count}."
        )
    for index in positions:
        payload[index + 1:index + 5] = replacement


def build_rect_minimap_cave(base: int, auto_cave: int, cave: int) -> bytes:
    payload = bytearray(base64.b64decode(RECT_MINIMAP_TEMPLATE_B64))
    if len(payload) > RECT_MINIMAP_CAVE_SIZE:
        fail("Rectangular minimap cave exceeds its allocation.")
    replacements = {
        0x11111111: auto_cave + AUTO_RECT_LOGICAL_WIDTH,
        0x22222222: auto_cave + AUTO_RECT_LOGICAL_HEIGHT,
        0x33333333: auto_cave + AUTO_RECT_ACTIVE_FLAG,
        0x44444446: base + RVA_UNIT_DIM_TABLE + 2,
        0x44444444: base + RVA_UNIT_DIM_TABLE,
        0x55555555: base + RVA_MINIMAP_CAMERA_COLOR,
        0x66666666: base + RVA_SCROLL_PIXEL_X,
        0x77777777: base + RVA_SCROLL_PIXEL_Y,
        0xC1C1C1C1: base + 0x51CB18,
        0xC2C2C2C2: base + 0x51CB1A,
        0xAAAAAAAA: base + RVA_MINIMAP_DRAW_FILLED,
        0xBBBBBBBB: base + RVA_MINIMAP_DRAW_OUTLINE,
        0xEEEEEEEE: base + RVA_MINIMAP_SHIFT,
        0xEFEFEFEF: base + 0x0D3DED,
        0xF0F0F0F0: base + 0x0D3ED5,
        0xF1F1F1F1: base + 0x0D4263,
        0x90909090: base + RVA_MINIMAP_TERRAIN_PTR,
        0x94949494: base + RVA_MINIMAP_GRAY_PTR,
        0x98989898: base + RVA_MINIMAP_LOCAL_PTR,
        0x9C9C9C9C: base + RVA_MINIMAP_SIDE,
        0xA1A1A1A1: cave + RECT_MINIMAP_STATE_TERRAIN_PTR,
        0xA2A2A2A2: cave + RECT_MINIMAP_STATE_GRAY_PTR,
        0xA3A3A3A3: cave + RECT_MINIMAP_STATE_LOCAL_PTR,
        0xA4A4A4A4: cave + RECT_MINIMAP_STATE_SIDE,
        0xA5A5A5A5: cave + RECT_MINIMAP_STATE_READY,
        0xA6A6A6A6: cave + RECT_MINIMAP_STATE_FOG_RETURN,
        0xA7A7A7A7: cave + RECT_MINIMAP_STATE_TERRAIN_RETURN,
        0xB1B1B1B1: cave + RECT_MINIMAP_STATE_FOG_SAVE_TERRAIN,
        0xB2B2B2B2: cave + RECT_MINIMAP_STATE_FOG_SAVE_GRAY,
        0xB3B3B3B3: cave + RECT_MINIMAP_STATE_FOG_SAVE_LOCAL,
        0xB4B4B4B4: cave + RECT_MINIMAP_STATE_FOG_SAVE_SIDE,
        0xC5C5C5C5: cave + RECT_MINIMAP_STATE_TERRAIN_SAVE_TERRAIN,
        0xC6C6C6C6: cave + RECT_MINIMAP_STATE_TERRAIN_SAVE_GRAY,
        0xC7C7C7C7: cave + RECT_MINIMAP_STATE_TERRAIN_SAVE_LOCAL,
        0xC8C8C8C8: cave + RECT_MINIMAP_STATE_TERRAIN_SAVE_SIDE,
        0xD1D1D1D1: cave + RECT_MINIMAP_ENTRY_OFFSETS["fog_restore"],
        0xD2D2D2D2: base + 0x10DCB5,
        0xD3D3D3D3: cave + RECT_MINIMAP_ENTRY_OFFSETS["terrain_restore"],
        0xD4D4D4D4: base + 0x10DE2B,
    }
    # A1/A3 repeated-byte placeholders sit next to x86 A1/A3 opcodes. Patch
    # only their moffs32 immediates so the opcodes cannot be overwritten.
    _replace_moffs32_load_immediates(
        payload, 0xA1A1A1A1, replacements.pop(0xA1A1A1A1), expected_count=2
    )
    _replace_moffs32_load_immediates(
        payload, 0xA3A3A3A3, replacements.pop(0xA3A3A3A3), expected_count=2
    )

    # Replace overlapping unit-table sentinels longest/specific first, then
    # replace all remaining placeholders using non-overlapping matches.
    for sentinel in (0x44444446, 0x44444444):
        _replace_u32_nonoverlap(payload, sentinel, replacements.pop(sentinel))
    for sentinel, value in replacements.items():
        _replace_u32_nonoverlap(payload, sentinel, value, expected_count=None)
    marker = RECT_MINIMAP_ENTRY_OFFSETS["marker"]
    if payload[marker:marker + len(RECT_MINIMAP_MARKER)] != RECT_MINIMAP_MARKER:
        fail("Rectangular minimap cave marker is missing.")
    # No unresolved magic address is allowed into the remote process.
    unresolved = [
        value for value in (
            0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x44444446,
            0x55555555, 0x66666666, 0x77777777, 0x90909090, 0x94949494,
            0x98989898, 0x9C9C9C9C, 0xA1A1A1A1, 0xA2A2A2A2,
            0xA3A3A3A3, 0xA4A4A4A4, 0xA5A5A5A5, 0xA6A6A6A6,
            0xA7A7A7A7, 0xB1B1B1B1, 0xB2B2B2B2, 0xB3B3B3B3,
            0xB4B4B4B4, 0xC5C5C5C5, 0xC6C6C6C6, 0xC7C7C7C7,
            0xC8C8C8C8, 0xD1D1D1D1, 0xD2D2D2D2, 0xD3D3D3D3,
            0xD4D4D4D4, 0xAAAAAAAA, 0xBBBBBBBB, 0xEEEEEEEE,
            0xEFEFEFEF, 0xF0F0F0F0, 0xF1F1F1F1,
        ) if struct.pack("<I", value) in payload
    ]
    if unresolved:
        fail(f"Rectangular minimap cave has unresolved sentinels: {unresolved}")
    return bytes(payload)


def install_or_restore_rect_minimap_hooks(
    kernel32, process, base: int, auto_cave: int | None,
    restore: bool, dry_run: bool,
) -> int | None:
    if not restore and auto_cave is None:
        fail("The 0.9 rectangle loader must be installed before minimap hooks.")
    originals = {
        rva: _runtime_mini_original(base, original)
        for rva, original, _entry, _length, _desc in RECT_MINIMAP_HOOK_SITES
    }
    current = {
        rva: read_memory(kernel32, process, base + rva, len(originals[rva]))
        for rva, _original, _entry, _length, _desc in RECT_MINIMAP_HOOK_SITES
    }
    stock = all(current[rva] == originals[rva] for rva in originals)

    def discover() -> int:
        for rva, _original, entry, _length, _desc in RECT_MINIMAP_HOOK_SITES:
            payload = current[rva]
            if payload[:1] == b"\xE9":
                return _mini_decode_target(base, rva, payload) - RECT_MINIMAP_ENTRY_OFFSETS[entry]
        fail("Rectangular minimap hooks are partially installed; restart Warcraft II.")

    if restore:
        if stock:
            print("[already restored] 0.9.5 rectangular minimap hooks")
            return None
        cave = discover()
        marker = read_memory(
            kernel32, process, cave + RECT_MINIMAP_ENTRY_OFFSETS["marker"],
            len(RECT_MINIMAP_MARKER),
        )
        if marker != RECT_MINIMAP_MARKER:
            fail("Installed minimap hooks do not belong to Lab 0.9.5.")
        print(f"[{'would restore' if dry_run else 'restore'}] rectangular minimap hooks")
        if not dry_run:
            for rva in originals:
                write_code(kernel32, process, base + rva, originals[rva])
        return cave

    if stock:
        if dry_run:
            print(f"[would install] {len(RECT_MINIMAP_HOOK_SITES)} minimap-only hooks (3 coordinate, 2 scoped raster)")
            return None
        pointer = kernel32.VirtualAllocEx(
            process, None, RECT_MINIMAP_CAVE_SIZE,
            MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE,
        )
        cave = ctypes.cast(pointer, ctypes.c_void_p).value if pointer else 0
        if not cave:
            fail(
                "VirtualAllocEx failed for minimap-only hooks: "
                f"Win32 error {ctypes.get_last_error()}"
            )
        cave = int(cave)
        payload = build_rect_minimap_cave(base, int(auto_cave), cave)
        write_data(kernel32, process, cave, payload)
        for rva, _original, entry, length, _desc in RECT_MINIMAP_HOOK_SITES:
            write_code(
                kernel32, process, base + rva,
                _mini_jump(base, rva, cave + RECT_MINIMAP_ENTRY_OFFSETS[entry], length),
            )
        print(
            f"[allocated] 0.9.5 minimap-only hook 0x{cave:08X}, {len(payload)} bytes; "
            f"{len(RECT_MINIMAP_HOOK_SITES)} minimap-only hooks (3 coordinate, 2 scoped raster)"
        )
        return cave

    cave = discover()
    marker = read_memory(
        kernel32, process, cave + RECT_MINIMAP_ENTRY_OFFSETS["marker"],
        len(RECT_MINIMAP_MARKER),
    )
    if marker != RECT_MINIMAP_MARKER:
        fail("A different minimap hook is installed; restart Warcraft II.")
    for rva, _original, entry, _length, desc in RECT_MINIMAP_HOOK_SITES:
        payload = current[rva]
        if payload[:1] != b"\xE9" or _mini_decode_target(base, rva, payload) != cave + RECT_MINIMAP_ENTRY_OFFSETS[entry]:
            fail(f"Minimap hook mismatch at RVA 0x{rva:06X} ({desc}).")
    print(f"[already patched] 0.9.5 minimap-only hooks -> 0x{cave:08X}")
    return cave


def allocate_rect_minimap_buffers(kernel32, process) -> int:
    pointer = kernel32.VirtualAllocEx(
        process, None, RECT_MINIMAP_BUFFER_SIZE,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE,
    )
    address = ctypes.cast(pointer, ctypes.c_void_p).value if pointer else 0
    if not address:
        fail(
            "VirtualAllocEx failed for rectangular minimap buffers: "
            f"Win32 error {ctypes.get_last_error()}"
        )
    return int(address)


def _resample_rect_minimap(
    terrain: bytes, gray: bytes, local: bytes,
    width: int, height: int, stride: int, target_side: int | None = None,
) -> tuple[bytes, bytes, bytes]:
    if not (1 <= width <= stride and 1 <= height <= stride <= 256):
        fail(f"Invalid rectangular minimap shape {width}x{height}/stride-{stride}.")
    if target_side is None:
        target_side = rect_minimap_raster_side(stride)
    if target_side not in MINIMAP_SCALE_BY_SIZE:
        fail(f"Unsupported rectangular minimap raster side {target_side}.")

    # Center-of-pixel sampling avoids a left/top bias when the ratio is not an
    # exact integer. For 32x96 this creates a 96x96 virtual minimap (3 samples
    # per source column), then Warcraft's stock 96-map scaler fills the panel.
    x_indices = [min(width - 1, ((2 * x + 1) * width) // (2 * target_side))
                 for x in range(target_side)]
    y_indices = [min(height - 1, ((2 * y + 1) * height) // (2 * target_side))
                 for y in range(target_side)]
    out_terrain = bytearray(target_side * target_side * 2)
    out_gray = bytearray(target_side * target_side)
    out_local = bytearray(target_side * target_side)
    destination = 0
    for sy in y_indices:
        row = sy * stride
        for sx in x_indices:
            source = row + sx
            word_source = source * 2
            word_destination = destination * 2
            out_terrain[word_destination:word_destination + 2] = terrain[word_source:word_source + 2]
            out_gray[destination] = gray[source]
            out_local[destination] = local[source]
            destination += 1
    return bytes(out_terrain), bytes(out_gray), bytes(out_local)


def update_rect_minimap_buffers(
    kernel32, process, base: int, buffer_base: int, minimap_hook_cave: int,
    width: int, height: int, stride: int,
    mt: int, gray_ptr: int, local_ptr: int,
) -> None:
    cells = stride * stride
    terrain = read_memory(kernel32, process, mt, cells * 2)
    gray = read_memory(kernel32, process, gray_ptr, cells)
    local = read_memory(kernel32, process, local_ptr, cells)
    target_side = rect_minimap_raster_side(stride)
    out_terrain, out_gray, out_local = _resample_rect_minimap(
        terrain, gray, local, width, height, stride, target_side
    )
    terrain_address = buffer_base + RECT_MINIMAP_TERRAIN_OFFSET
    gray_address = buffer_base + RECT_MINIMAP_GRAY_OFFSET
    local_address = buffer_base + RECT_MINIMAP_LOCAL_OFFSET
    # Make all five hooks fall back to the untouched 0.9.0 path while the
    # monitor refreshes the three remote buffers.
    write_data(kernel32, process, minimap_hook_cave + RECT_MINIMAP_STATE_READY, b"\x00")
    write_data(kernel32, process, terrain_address, out_terrain)
    write_data(kernel32, process, gray_address, out_gray)
    write_data(kernel32, process, local_address, out_local)

    # Publish buffers to the cave. The scoped wrappers swap the shared renderer
    # globals only while the two classic minimap raster functions execute.
    # World rendering and every square map retain the exact 0.9.0 bindings.
    write_u32(kernel32, process, minimap_hook_cave + RECT_MINIMAP_STATE_TERRAIN_PTR, terrain_address)
    write_u32(kernel32, process, minimap_hook_cave + RECT_MINIMAP_STATE_GRAY_PTR, gray_address)
    write_u32(kernel32, process, minimap_hook_cave + RECT_MINIMAP_STATE_LOCAL_PTR, local_address)
    write_u16(kernel32, process, minimap_hook_cave + RECT_MINIMAP_STATE_SIDE, target_side)
    write_data(kernel32, process, minimap_hook_cave + RECT_MINIMAP_STATE_READY, b"\x01")
    enforce_minimap_scale(kernel32, process, base, target_side)
    write_u16(kernel32, process, base + RVA_MINIMAP_REDRAW_TIMER, 1)


def disable_rect_minimap_buffers(kernel32, process, minimap_hook_cave: int) -> None:
    write_data(kernel32, process, minimap_hook_cave + RECT_MINIMAP_STATE_READY, b"\x00")


def build_dynamic_size_cave(base: int, cave_address: int) -> bytes:
    """Generate the x86 scenario-size hook with ASLR-correct absolute addresses."""
    code = bytearray()
    labels: dict[str, int] = {}
    fixups: list[tuple[int, str]] = []

    def emit(payload: bytes) -> None:
        code.extend(payload)

    def mark(name: str) -> None:
        labels[name] = len(code)

    def emit_label_jump(opcode: bytes, label: str) -> None:
        emit(opcode)
        position = len(code)
        emit(b"\x00\x00\x00\x00")
        fixups.append((position, label))

    def relative32(source_after: int, destination: int) -> bytes:
        displacement = destination - source_after
        if not -(1 << 31) <= displacement < (1 << 31):
            fail("Dynamic-size hook branch is outside x86 rel32 range.")
        return struct.pack("<i", displacement)

    # Preserve all caller state while calculating the transfer lengths.
    emit(b"\x9C\x60")  # pushfd; pushad
    emit(b"\x0F\xB7\x05" + struct.pack("<I", base + RVA_MAP_WIDTH))
    emit(b"\x3D\x80\x00\x00\x00")  # cmp eax, 128
    emit_label_jump(b"\x0F\x87", "extended")  # ja extended
    emit(b"\xB8\x00\x40\x00\x00")  # stock working cells = 128*128
    emit_label_jump(b"\xE9", "sizes")
    mark("extended")
    emit(b"\x0F\xAF\xC0")  # imul eax, eax -> width*width
    mark("sizes")
    emit(b"\x8B\xD8\x03\xDB")  # ebx = cells*2
    emit(b"\x8B\xCB\x03\xC9")  # ecx = cells*4

    # The opcode remains PUSH imm32; only its four-byte immediate is updated.
    for rva in DYNAMIC_BYTE_SIZE_RVAS:
        emit(b"\xA3" + struct.pack("<I", base + rva + 1))
    for rva in DYNAMIC_WORD_SIZE_RVAS:
        emit(b"\x89\x1D" + struct.pack("<I", base + rva + 1))
    for rva in DYNAMIC_DWORD_SIZE_RVAS:
        emit(b"\x89\x0D" + struct.pack("<I", base + rva + 1))

    emit(b"\x33\xC0\x0F\xA2")  # xor eax,eax; cpuid (serialize code writes)
    emit(b"\x61\x9D")          # popad; popfd
    emit(b"\x85\xFF")          # displaced: test edi, edi

    # Reproduce the original branch exactly after updating the sizes.
    emit(b"\x0F\x84")
    emit(relative32(
        cave_address + len(code) + 4,
        base + 0x0C64FA,
    ))
    emit(b"\xE9")
    emit(relative32(
        cave_address + len(code) + 4,
        base + 0x0C6450,
    ))
    emit(DYNAMIC_SIZE_HOOK_MARKER)

    for position, label in fixups:
        code[position:position + 4] = relative32(
            cave_address + position + 4,
            cave_address + labels[label],
        )

    if len(code) > DYNAMIC_SIZE_CAVE_SIZE:
        fail("Dynamic-size hook exceeds its allocation.")
    return bytes(code)


def dynamic_hook_jump(base: int, cave_address: int) -> bytes:
    source_after = base + RVA_DYNAMIC_SIZE_HOOK + 5
    displacement = cave_address - source_after
    if not -(1 << 31) <= displacement < (1 << 31):
        fail("Allocated dynamic-size cave is outside x86 rel32 range.")
    return b"\xE9" + struct.pack("<i", displacement) + b"\x90\x90\x90"


def decode_dynamic_hook_target(base: int, payload: bytes) -> int:
    if len(payload) != 8 or payload[0] != 0xE9 or payload[5:] != b"\x90\x90\x90":
        fail("Dynamic-size hook bytes are not recognized.")
    displacement = struct.unpack("<i", payload[1:5])[0]
    return base + RVA_DYNAMIC_SIZE_HOOK + 5 + displacement


def set_dynamic_code_pages(
    kernel32,
    process,
    base: int,
    protection: int,
) -> None:
    page_addresses = {
        (base + rva) & ~0xFFF
        for rva in DYNAMIC_SIZE_RVAS | {RVA_DYNAMIC_SIZE_HOOK, RVA_DIM_HANDLER, RVA_RECT_MTXM_TAIL, RVA_RECT_SQM_TAIL, RVA_RECT_REGM_TAIL}
    }
    for address in sorted(page_addresses):
        old_protect = wintypes.DWORD()
        if not kernel32.VirtualProtectEx(
            process,
            ctypes.c_void_p(address),
            0x1000,
            protection,
            ctypes.byref(old_protect),
        ):
            fail(
                f"VirtualProtectEx failed for dynamic page 0x{address:08X}: "
                f"Win32 error {ctypes.get_last_error()}"
            )


def install_or_restore_dynamic_size_hook(
    kernel32,
    process,
    base: int,
    restore: bool,
    dry_run: bool,
) -> int | None:
    hook_address = base + RVA_DYNAMIC_SIZE_HOOK
    current = read_memory(
        kernel32, process, hook_address, len(DYNAMIC_SIZE_HOOK_ORIGINAL)
    )

    if restore:
        if current == DYNAMIC_SIZE_HOOK_ORIGINAL:
            print("[already restored] automatic map-size compatibility hook")
            return None
        cave_address = decode_dynamic_hook_target(base, current)
        marker_address = cave_address + len(build_dynamic_size_cave(base, cave_address)) - len(
            DYNAMIC_SIZE_HOOK_MARKER
        )
        marker = read_memory(
            kernel32, process, marker_address, len(DYNAMIC_SIZE_HOOK_MARKER)
        )
        if marker != DYNAMIC_SIZE_HOOK_MARKER:
            fail("Existing scenario hook does not belong to this lab.")
        print(
            f"[{'would restore' if dry_run else 'restore'}] automatic map-size "
            f"hook at RVA 0x{RVA_DYNAMIC_SIZE_HOOK:06X}"
        )
        if not dry_run:
            write_code(
                kernel32, process, hook_address, DYNAMIC_SIZE_HOOK_ORIGINAL
            )
        return cave_address

    if current == DYNAMIC_SIZE_HOOK_ORIGINAL:
        if dry_run:
            print(
                "[would install] automatic normal/extended map-size compatibility hook"
            )
            return None
        cave_pointer = kernel32.VirtualAllocEx(
            process,
            None,
            DYNAMIC_SIZE_CAVE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        )
        cave_address = ctypes.cast(cave_pointer, ctypes.c_void_p).value if cave_pointer else 0
        if not cave_address:
            fail(
                "VirtualAllocEx failed for the map-size hook: "
                f"Win32 error {ctypes.get_last_error()}"
            )
        cave_address = int(cave_address)
        cave = build_dynamic_size_cave(base, cave_address)
        write_data(kernel32, process, cave_address, cave)
        set_dynamic_code_pages(kernel32, process, base, PAGE_EXECUTE_READWRITE)
        write_code(
            kernel32,
            process,
            hook_address,
            dynamic_hook_jump(base, cave_address),
        )
        print(
            f"[allocated] automatic map-size hook 0x{cave_address:08X}, "
            f"{len(cave)} bytes; manages {len(DYNAMIC_SIZE_RVAS)} transfer sites"
        )
        return cave_address

    cave_address = decode_dynamic_hook_target(base, current)
    expected = build_dynamic_size_cave(base, cave_address)
    marker = read_memory(
        kernel32,
        process,
        cave_address + len(expected) - len(DYNAMIC_SIZE_HOOK_MARKER),
        len(DYNAMIC_SIZE_HOOK_MARKER),
    )
    if marker != DYNAMIC_SIZE_HOOK_MARKER:
        fail("Existing scenario hook does not belong to this lab.")
    set_dynamic_code_pages(kernel32, process, base, PAGE_EXECUTE_READWRITE)
    print(
        f"[already patched] automatic map-size hook -> 0x{cave_address:08X}"
    )
    return cave_address


def desired_dynamic_sizes(map_width: int) -> tuple[int, int, int]:
    cells = 0x4000 if map_width <= 128 else map_width * map_width
    if cells > 0x10000:
        fail(f"Unsupported live map width {map_width}; maximum is 256.")
    return cells, cells * 2, cells * 4


def sync_dynamic_size_immediates(
    kernel32,
    process,
    base: int,
    map_width: int,
    announce: bool = False,
) -> tuple[int, int, int]:
    byte_size, word_size, dword_size = desired_dynamic_sizes(map_width)
    groups = [
        (DYNAMIC_BYTE_SIZE_RVAS, byte_size),
        (DYNAMIC_WORD_SIZE_RVAS, word_size),
        (DYNAMIC_DWORD_SIZE_RVAS, dword_size),
    ]
    changed = 0
    for rvas, size in groups:
        payload = struct.pack("<I", size)
        for rva in rvas:
            opcode = read_memory(kernel32, process, base + rva, 1)
            if opcode != b"\x68":
                fail(f"Dynamic transfer site RVA 0x{rva:06X} lost its PUSH opcode.")
            current = read_memory(kernel32, process, base + rva + 1, 4)
            if current != payload:
                write_data(kernel32, process, base + rva + 1, payload)
                changed += 1
    if announce and changed:
        print(
            f"[sizes] {map_width}x{map_width}: byte=0x{byte_size:X}, "
            f"word=0x{word_size:X}, dword=0x{dword_size:X}; "
            f"updated {changed} sites"
        )
    return byte_size, word_size, dword_size


def inspect_nav_xrefs(kernel32, process, base: int) -> tuple[int, list[int]]:
    stock_address = base + RVA_NAV_BLOCK_BUFFER
    values = [
        struct.unpack("<I", read_memory(kernel32, process, base + rva, 4))[0]
        for rva in NAV_BLOCK_BUFFER_XREF_RVAS
    ]
    return stock_address, values


def patch_nav_block_buffer(
    kernel32,
    process,
    base: int,
    restore: bool,
    dry_run: bool,
) -> int | None:
    stock_address, values = inspect_nav_xrefs(kernel32, process, base)
    unique = sorted(set(values))

    if restore:
        if unique == [stock_address]:
            print("[already restored] extended navigation buffer references")
            return None
        if len(unique) != 1:
            formatted = ", ".join(f"0x{x:08X}" for x in unique)
            fail(f"Navigation-buffer xrefs disagree during restore: {formatted}")
        old_dynamic = unique[0]
        print(
            f"[{'would restore' if dry_run else 'restore'}] navigation buffer "
            f"0x{old_dynamic:08X} -> stock 0x{stock_address:08X}"
        )
        if not dry_run:
            payload = struct.pack("<I", stock_address)
            for rva in NAV_BLOCK_BUFFER_XREF_RVAS:
                write_code(kernel32, process, base + rva, payload)
            # Do not free the old allocation here. A still-loaded scenario may
            # retain transient pointers into it; process exit reclaims it safely.
        return old_dynamic

    if unique == [stock_address]:
        if dry_run:
            print(
                "[would allocate] 0x10800-byte navigation buffer and redirect "
                f"{len(NAV_BLOCK_BUFFER_XREF_RVAS)} references"
            )
            return None
        dynamic_address = allocate_nav_block_buffer(kernel32, process)
        payload = struct.pack("<I", dynamic_address)
        try:
            for rva in NAV_BLOCK_BUFFER_XREF_RVAS:
                write_code(kernel32, process, base + rva, payload)
        except Exception:
            kernel32.VirtualFreeEx(
                process, ctypes.c_void_p(dynamic_address), 0, MEM_RELEASE
            )
            raise
        print(
            f"[allocated] navigation buffer 0x{dynamic_address:08X}, "
            f"size 0x{NAV_BLOCK_BUFFER_EXTENDED_SIZE:X}; redirected "
            f"{len(NAV_BLOCK_BUFFER_XREF_RVAS)} references"
        )
        return dynamic_address

    if len(unique) == 1:
        dynamic_address = unique[0]
        if base <= dynamic_address < base + EXPECTED_IMAGE_SIZE:
            fail(
                "Navigation-buffer references point inside the module but not "
                f"at the expected stock address: 0x{dynamic_address:08X}"
            )
        print(
            f"[already patched] navigation buffer references -> "
            f"0x{dynamic_address:08X}"
        )
        return dynamic_address

    formatted = ", ".join(f"0x{x:08X}" for x in unique)
    fail(f"Navigation-buffer xrefs disagree: {formatted}")


def verify_executable(path: Path) -> None:
    digest = sha256_file(path)
    timestamp, image_size = parse_pe_identity(path)
    print(f"Executable: {path}")
    print(f"SHA-256:   {digest}")
    print(f"PE stamp:  0x{timestamp:08X}")
    print(f"Image size: 0x{image_size:X}")
    if digest.lower() != EXPECTED_SHA256:
        fail(
            "Unsupported Warcraft II executable. This lab only patches the exact "
            f"{EXPECTED_VERSION} file with SHA-256 {EXPECTED_SHA256}."
        )
    if timestamp != EXPECTED_TIMESTAMP or image_size != EXPECTED_IMAGE_SIZE:
        fail("PE identity mismatch even though the file hash was expected.")


def apply_or_restore(kernel32, process, base: int, restore: bool, dry_run: bool) -> None:
    changed = 0
    already = 0
    action = "restore" if restore else "patch"
    for rva, original, patched, description in PATCHES:
        address = base + rva
        runtime_original, runtime_patched = resolve_runtime_patch(
            base, rva, original, patched
        )
        current = read_memory(kernel32, process, address, len(runtime_original))
        desired = runtime_original if restore else runtime_patched
        alternate = runtime_patched if restore else runtime_original
        if current == desired:
            already += 1
            print(f"[already {action}ed] RVA 0x{rva:06X}  {description}")
            continue
        if rva in DYNAMIC_SIZE_RVAS and len(current) == 5 and current[:1] == b"\x68":
            if not restore:
                already += 1
                value = struct.unpack("<I", current[1:])[0]
                print(
                    f"[dynamic] RVA 0x{rva:06X}  {description}: "
                    f"current immediate 0x{value:X}"
                )
                continue
            # Restore accepts any dimension-derived immediate and writes stock.
        elif current != alternate:
            fail(
                f"Unexpected bytes at RVA 0x{rva:06X} ({description}).\n"
                f"Expected {alternate.hex(' ')}, found {current.hex(' ')}.\n"
                "No additional patches were written after this mismatch."
            )
        print(
            f"[{'would write' if dry_run else 'write'}] RVA 0x{rva:06X}  "
            f"{current.hex(' ')} -> {desired.hex(' ')}  {description}"
        )
        if not dry_run:
            write_code(kernel32, process, address, desired)
        changed += 1
    print(f"Patch records: {len(PATCHES)}; changed: {changed}; already correct: {already}")


def read_u16(kernel32, process, address: int) -> int:
    return struct.unpack("<H", read_memory(kernel32, process, address, 2))[0]


def read_u32(kernel32, process, address: int) -> int:
    return struct.unpack("<I", read_memory(kernel32, process, address, 4))[0]


def write_u16(kernel32, process, address: int, value: int) -> None:
    write_data(kernel32, process, address, struct.pack("<H", value & 0xFFFF))


def write_u32(kernel32, process, address: int, value: int) -> None:
    write_data(kernel32, process, address, struct.pack("<I", value & 0xFFFFFFFF))


def enforce_minimap_scale(kernel32, process, base: int, map_size: int) -> tuple[int, int, int] | None:
    desired = MINIMAP_SCALE_BY_SIZE.get(map_size)
    if desired is None:
        return None
    divisor, adjustment, shift = desired
    current = (
        read_u16(kernel32, process, base + RVA_MINIMAP_DIVISOR),
        read_u16(kernel32, process, base + RVA_MINIMAP_DIV_ADJUST),
        read_u16(kernel32, process, base + RVA_MINIMAP_SHIFT),
    )
    if current != desired:
        write_u16(kernel32, process, base + RVA_MINIMAP_DIVISOR, divisor)
        write_u16(kernel32, process, base + RVA_MINIMAP_DIV_ADJUST, adjustment)
        write_u16(kernel32, process, base + RVA_MINIMAP_SHIFT, shift)
        # Request a prompt redraw after correcting a map-size transition.
        write_u16(kernel32, process, base + RVA_MINIMAP_REDRAW_TIMER, 1)
        print(
            f"[minimap] corrected {map_size}x{map_size} scale: "
            f"(tile << {shift}) / {divisor}, adjust={adjustment}"
        )
    return desired


def read_i32(kernel32, process, address: int) -> int:
    return struct.unpack("<i", read_memory(kernel32, process, address, 4))[0]


def write_i32(kernel32, process, address: int, value: int) -> None:
    write_data(kernel32, process, address, struct.pack("<i", int(value)))



def read_auto_rectangle_state(kernel32, process, cave_address: int) -> tuple[int, int, int, bool, bool]:
    # Read the state as one compact snapshot. Earlier builds performed five
    # separate ReadProcessMemory calls every 25 ms, making a process-exit or
    # page-transition race much more likely to surface as Win32 error 299.
    state = read_memory(kernel32, process, cave_address + AUTO_RECT_LOGICAL_WIDTH, 9)
    width, height, side = struct.unpack_from("<HHH", state, 0)
    active = bool(state[6])
    expanded = bool(state[8])
    return width, height, side, active, expanded


def resolve_auto_rectangle_cave(kernel32, process, base: int) -> int:
    """Resolve and validate the currently installed rectangle cave."""
    payload = read_memory(kernel32, process, base + RVA_DYNAMIC_SIZE_HOOK, 8)
    cave_address = decode_hook_target(base, RVA_DYNAMIC_SIZE_HOOK, payload)
    marker = read_memory(
        kernel32, process, cave_address + AUTO_RECT_MARKER_OFFSET, len(AUTO_RECT_MARKER)
    )
    if marker != AUTO_RECT_MARKER:
        fail("The installed rectangle hook marker is missing or belongs to another build.")
    return cave_address


def _mask_padding_in_buffer(
    kernel32,
    process,
    pointer: int,
    width: int,
    height: int,
    side: int,
    fill: int,
) -> bool:
    """Force only the square-storage padding to a fixed byte value.

    The authored rectangle remains byte-for-byte unchanged. Reading and writing
    one snapshot avoids hundreds of tiny WriteProcessMemory calls while still
    preserving live fog state inside the real map.
    """
    if not pointer or not (1 <= width <= side and 1 <= height <= side):
        return False
    size = side * side
    data = bytearray(read_memory(kernel32, process, pointer, size))
    changed = False
    fill_byte = fill & 0xFF
    for y in range(side):
        x0 = width if y < height else 0
        if x0 >= side:
            continue
        start = y * side + x0
        end = (y + 1) * side
        segment = data[start:end]
        if any(value != fill_byte for value in segment):
            data[start:end] = bytes([fill_byte]) * (end - start)
            changed = True
    if changed:
        write_data(kernel32, process, pointer, bytes(data))
    return changed


def _mask_padding_in_word_buffer(
    kernel32,
    process,
    pointer: int,
    width: int,
    height: int,
    side: int,
    fill: int,
) -> bool:
    if not pointer or not (1 <= width <= side and 1 <= height <= side):
        return False
    size = side * side
    raw = bytearray(read_memory(kernel32, process, pointer, size * 2))
    changed = False
    fill_word = struct.pack("<H", fill & 0xFFFF)
    for y in range(side):
        x0 = width if y < height else 0
        if x0 >= side:
            continue
        start = (y * side + x0) * 2
        end = ((y + 1) * side) * 2
        expected = fill_word * ((end - start) // 2)
        if raw[start:end] != expected:
            raw[start:end] = expected
            changed = True
    if changed:
        write_data(kernel32, process, pointer, bytes(raw))
    return changed


def mask_logical_rectangle_padding(
    kernel32,
    process,
    base: int,
    width: int,
    height: int,
    side: int,
) -> bool:
    """Keep internal square padding black, hidden, and unreachable."""
    # Byte-per-cell state: outside map is permanently black, unseen and
    # unreachable. These are re-applied because vision updates can touch the
    # square backing padding near a logical edge.
    byte_specs = (
        (RVA_GRAY_MASK_PTR, H_ALL),
        (RVA_LOCAL_MASK_PTR, H_ALL),
        (RVA_ALL_PLAYER_MASK_PTR, NO_FACE),
        (RVA_TRAVERSAL_MAP_PTR, NO_FACE),
    )
    changed = False
    for pointer_rva, fill in byte_specs:
        pointer = read_u32(kernel32, process, base + pointer_rva)
        changed |= _mask_padding_in_buffer(
            kernel32, process, pointer, width, height, side, fill
        )

    # Source-derived gameplay guards. SQM 0x0081 is hard-blocked terrain and
    # REGM 0xFFFD is the stock rock/outside-region sentinel used by the current
    # parser expansion. Reasserting them prevents building/pathing code that
    # still uses the square stride from treating padding as ordinary ground.
    sqm_pointer = read_u32(kernel32, process, base + RVA_SQM_PTR)
    regm_pointer = read_u32(kernel32, process, base + RVA_REGM_PTR)
    changed |= _mask_padding_in_word_buffer(
        kernel32, process, sqm_pointer, width, height, side, 0x0081
    )
    changed |= _mask_padding_in_word_buffer(
        kernel32, process, regm_pointer, width, height, side, 0xFFFD
    )
    if changed:
        # Force the minimap to consume the corrected mask state promptly.
        write_u16(kernel32, process, base + RVA_MINIMAP_REDRAW_TIMER, 1)
    return changed


def clamp_logical_rectangle(kernel32, process, base: int, width: int, height: int) -> bool:
    viewport_w = read_u16(kernel32, process, base + RVA_VIEWPORT_PIXEL_WIDTH)
    viewport_h = read_u16(kernel32, process, base + RVA_VIEWPORT_PIXEL_HEIGHT)
    max_x = max(0, width * TILE_PIXELS - viewport_w)
    max_y = max(0, height * TILE_PIXELS - viewport_h)
    x_addr = base + RVA_SCROLL_PIXEL_X
    y_addr = base + RVA_SCROLL_PIXEL_Y
    x = read_i32(kernel32, process, x_addr)
    y = read_i32(kernel32, process, y_addr)
    fixed_x = min(max(x, 0), max_x)
    fixed_y = min(max(y, 0), max_y)
    changed = False
    if fixed_x != x:
        write_i32(kernel32, process, x_addr, fixed_x)
        changed = True
    if fixed_y != y:
        write_i32(kernel32, process, y_addr, fixed_y)
        changed = True
    return changed


def monitor(kernel32, process, base: int, cave_address: int, minimap_buffer_base: int, minimap_hook_cave: int) -> None:
    print("\nPatch is active in RAM. Load the original PUD directly—no BAT conversion is needed.")
    print("Press Ctrl+C to stop monitoring; the RAM patch remains active until Warcraft exits.")
    previous = None
    clamp_announced = False
    padding_announced = False
    cached_rect_state: tuple[int, int, int, bool, bool] | None = None
    cave_failures = 0
    cave_warning_printed = False
    rectangular_minimap_announced = False
    rectangle_minimap_was_active = False
    minimap_last_update = 0.0

    while True:
        # 100 ms is plenty for camera clamping and avoids hammering the remote
        # process with roughly 200 memory reads per second.
        result = kernel32.WaitForSingleObject(process, 100)
        if result != WAIT_TIMEOUT:
            print("Warcraft II process exited.")
            return

        # Cave status is diagnostic/control state. A transient ERROR_PARTIAL_COPY
        # must not terminate the patcher or disable camera clamping.
        try:
            rect_state = read_auto_rectangle_state(kernel32, process, cave_address)
            cached_rect_state = rect_state
            cave_failures = 0
            cave_warning_printed = False
        except RuntimeError as exc:
            cave_failures += 1
            # Re-resolve the cave from the live JMP in case the patch was
            # reinstalled by another Lab instance.
            try:
                cave_address = resolve_auto_rectangle_cave(kernel32, process, base)
                rect_state = read_auto_rectangle_state(kernel32, process, cave_address)
                cached_rect_state = rect_state
                cave_failures = 0
                cave_warning_printed = False
            except RuntimeError:
                if cached_rect_state is None:
                    if not cave_warning_printed:
                        print(f"[monitor] temporary rectangle-state read failure; retrying: {exc}")
                        cave_warning_printed = True
                    continue
                rect_state = cached_rect_state
                if not cave_warning_printed:
                    print(
                        "[monitor] rectangle-state page was temporarily unreadable; "
                        "using the last valid dimensions and continuing."
                    )
                    cave_warning_printed = True

        width, height, storage_side, active, expanded = rect_state

        try:
            map_side = read_u16(kernel32, process, base + RVA_MAP_WIDTH)
            scale = None
            mt = read_u32(kernel32, process, base + RVA_MTXM_PTR)
            sqm = read_u32(kernel32, process, base + RVA_SQM_PTR)
            regm = read_u32(kernel32, process, base + RVA_REGM_PTR)
            gray_ptr = read_u32(kernel32, process, base + RVA_GRAY_MASK_PTR)
            local_ptr = read_u32(kernel32, process, base + RVA_LOCAL_MASK_PTR)
        except RuntimeError as exc:
            # This usually means the process is in the middle of shutting down.
            if kernel32.WaitForSingleObject(process, 0) != WAIT_TIMEOUT:
                print("Warcraft II process exited.")
                return
            print(f"[monitor] game globals temporarily unreadable; retrying: {exc}")
            continue

        loaded = active and expanded and all((mt, sqm, regm)) and storage_side == map_side
        is_rectangle = loaded and width != height
        if is_rectangle:
            now = time.monotonic()
            if now - minimap_last_update >= 0.10:
                try:
                    update_rect_minimap_buffers(
                        kernel32, process, base, minimap_buffer_base, minimap_hook_cave,
                        width, height, storage_side, mt, gray_ptr, local_ptr,
                    )
                    minimap_last_update = now
                    scale = (1, 0, 0)
                    rectangle_minimap_was_active = True
                    if not rectangular_minimap_announced:
                        print(
                            f"[minimap-only] resampling logical {width}x{height} from "
                            f"the proven 0.9.0 {storage_side}x{storage_side} backing grid into a {rect_minimap_raster_side(storage_side)}x{rect_minimap_raster_side(storage_side)} native raster"
                        )
                        print("[minimap-only] Warcraft performs the final native stretch to the full 128x128 panel")
                        rectangular_minimap_announced = True
                except RuntimeError as exc:
                    if kernel32.WaitForSingleObject(process, 0) != WAIT_TIMEOUT:
                        print("Warcraft II process exited.")
                        return
                    print(f"[minimap-only] refresh skipped for one cycle: {exc}")
        else:
            scale = enforce_minimap_scale(kernel32, process, base, map_side)
            rectangular_minimap_announced = False
            if rectangle_minimap_was_active:
                try:
                    disable_rect_minimap_buffers(kernel32, process, minimap_hook_cave)
                    if loaded:
                        print(f"[minimap-only] native 0.9.0 square path active: {map_side}x{map_side}")
                except RuntimeError as exc:
                    print(f"[minimap-only] rectangle bypass deferred: {exc}")
                rectangle_minimap_was_active = False
        if loaded and 1 <= width <= 256 and 1 <= height <= 256:
            try:
                padding_changed = mask_logical_rectangle_padding(
                    kernel32, process, base, width, height, storage_side
                )
                if (width != storage_side or height != storage_side) and not padding_announced:
                    print(
                        "[all-size] outside-map padding locked black, blocked and unreachable"
                    )
                    padding_announced = True
                clamp_logical_rectangle(kernel32, process, base, width, height)
            except RuntimeError as exc:
                if kernel32.WaitForSingleObject(process, 0) != WAIT_TIMEOUT:
                    print("Warcraft II process exited.")
                    return
                print(f"[monitor] camera clamp skipped for one cycle: {exc}")
            if not clamp_announced:
                plan = dimension_plan(width, height)
                print(
                    f"[all-size] raw PUD accepted: logical {width}x{height}, "
                    f"stride {storage_side}, compact={plan.compact_cells} cells, "
                    f"padding={plan.padding_cells} cells"
                )
                print(
                    f"[all-size] camera bounds active: X 0-{width - 1}, Y 0-{height - 1}"
                )
                clamp_announced = True
        else:
            clamp_announced = False
            padding_announced = False

        state = (width, height, storage_side, active, expanded, map_side, scale, mt, sqm, regm)
        if state != previous:
            if loaded:
                print(
                    f"Live map: logical {width}x{height} | storage {storage_side}x{storage_side} | "
                    f"MTXM=0x{mt:08X} SQM=0x{sqm:08X} REGM=0x{regm:08X}"
                )
            else:
                print(
                    f"Live map: {map_side}x{map_side} | MTXM=0x{mt:08X} "
                    f"SQM=0x{sqm:08X} REGM=0x{regm:08X}"
                )
            previous = state

def main() -> int:
    parser = argparse.ArgumentParser(
        description=f"War2 Extended Map Lab {LAB_VERSION} for Warcraft II Remastered 1.0.2.2818."
    )
    parser.add_argument("--pid", type=int, help="Attach to a specific Warcraft II.exe PID.")
    parser.add_argument("--restore", action="store_true", help="Restore original code bytes in the running process.")
    parser.add_argument("--dry-run", action="store_true", help="Verify every patch location without writing memory.")
    parser.add_argument("--no-monitor", action="store_true", help="Exit immediately after patching.")
    parser.add_argument(
        "--self-test-all-sizes", action="store_true",
        help="Exhaustively validate all 65,536 width/height combinations without attaching to the game.",
    )
    parser.add_argument(
        "--plan", nargs=2, type=int, metavar=("WIDTH", "HEIGHT"),
        help="Print the logical/storage plan for one dimension pair and exit.",
    )
    args = parser.parse_args()

    if args.self_test_all_sizes:
        result = exhaustive_dimension_self_test()
        print(
            f"All-size self-test passed: {result['combinations']} combinations, "
            f"{result['stride_buckets']} stride buckets, "
            f"max padding {result['max_padding_cells']} cells."
        )
        return 0
    if args.plan:
        plan = dimension_plan(args.plan[0], args.plan[1])
        print(json.dumps(plan.__dict__, indent=2, sort_keys=True))
        return 0

    if os.name != "nt":
        print("This runtime patcher must be run on Windows.", file=sys.stderr)
        return 2

    kernel32 = configure_api()
    process = None
    cave_address = None
    minimap_hook_cave = None
    try:
        pid, base, exe_path = find_target(kernel32, args.pid)
        print(f"PID: {pid}")
        print(f"Module base: 0x{base:08X}")
        verify_executable(exe_path)
        process = open_target(kernel32, pid)
        patch_nav_block_buffer(
            kernel32, process, base, args.restore, args.dry_run
        )
        if args.restore:
            try:
                installed_auto = resolve_auto_rectangle_cave(kernel32, process, base)
            except RuntimeError:
                installed_auto = None
            install_or_restore_rect_scroll_hooks(
                kernel32, process, base, installed_auto, True, args.dry_run
            )
            install_or_restore_rect_minimap_hooks(
                kernel32, process, base, installed_auto, True, args.dry_run
            )
            install_or_restore_auto_rectangle_hook(
                kernel32, process, base, True, args.dry_run
            )
            apply_or_restore(kernel32, process, base, True, args.dry_run)
            if not args.dry_run:
                set_dynamic_code_pages(
                    kernel32, process, base, PAGE_EXECUTE_READ
                )
        else:
            apply_or_restore(kernel32, process, base, False, args.dry_run)
            cave_address = install_or_restore_auto_rectangle_hook(
                kernel32, process, base, False, args.dry_run
            )
            install_or_restore_rect_scroll_hooks(
                kernel32, process, base, cave_address, False, args.dry_run
            )
            minimap_hook_cave = install_or_restore_rect_minimap_hooks(
                kernel32, process, base, cave_address, False, args.dry_run
            )
        if not args.restore and not args.dry_run and not args.no_monitor:
            if cave_address is None or minimap_hook_cave is None:
                fail("Rectangle loader or minimap-only cave address was not available.")
            minimap_buffer_base = allocate_rect_minimap_buffers(kernel32, process)
            print(
                f"[allocated] rectangular minimap buffers 0x{minimap_buffer_base:08X}, "
                f"size 0x{RECT_MINIMAP_BUFFER_SIZE:X}"
            )
            monitor(kernel32, process, base, cave_address, minimap_buffer_base, int(minimap_hook_cave))
        return 0
    except KeyboardInterrupt:
        print("\nMonitoring stopped. The running game remains patched until it exits.")
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        if process:
            close_handle(kernel32, process)


if __name__ == "__main__":
    raise SystemExit(main())
