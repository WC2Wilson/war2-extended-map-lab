from __future__ import annotations

from pathlib import Path
import hashlib
import struct
import sys

import war2_extended_map_lab as lab

ROOT = Path(__file__).resolve().parent
DEFAULT_EXE = None


def parse_sections(raw: bytes) -> list[tuple[int, int, int, int, bytes]]:
    if raw[:2] != b"MZ":
        raise ValueError("not a PE file")
    pe = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[pe:pe + 4] != b"PE\0\0":
        raise ValueError("invalid PE signature")
    section_count = struct.unpack_from("<H", raw, pe + 6)[0]
    opt_size = struct.unpack_from("<H", raw, pe + 20)[0]
    sec_off = pe + 24 + opt_size
    out = []
    for i in range(section_count):
        off = sec_off + i * 40
        name = raw[off:off + 8].rstrip(b"\0")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", raw, off + 8)
        out.append((virtual_address, max(virtual_size, raw_size), raw_offset, raw_size, name))
    return out


def rva_to_offset(raw: bytes, rva: int) -> int:
    for va, size, raw_off, raw_size, _name in parse_sections(raw):
        if va <= rva < va + size:
            delta = rva - va
            if delta >= raw_size:
                raise ValueError(f"RVA 0x{rva:X} lies in virtual-only section data")
            return raw_off + delta
    raise ValueError(f"RVA 0x{rva:X} not found in PE sections")


def read_rva(raw: bytes, rva: int, size: int) -> bytes:
    off = rva_to_offset(raw, rva)
    return raw[off:off + size]


def verify(exe_path: Path) -> list[str]:
    raw = exe_path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != lab.EXPECTED_SHA256:
        raise AssertionError(f"SHA-256 mismatch: {digest}")

    checked = 0
    for rva, original, _patched, description in lab.PATCHES:
        actual = read_rva(raw, rva, len(original))
        if actual != original:
            raise AssertionError(
                f"patch mismatch at RVA 0x{rva:06X} ({description}): "
                f"expected {original.hex(' ')}, found {actual.hex(' ')}"
            )
        checked += 1

    hook_sites = [
        (lab.RVA_DYNAMIC_SIZE_HOOK, lab.DYNAMIC_SIZE_HOOK_ORIGINAL, "scenario-size hook"),
        (lab.RVA_DIM_HANDLER, lab.DIM_HOOK_ORIGINAL, "DIM hook"),
        (lab.RVA_RECT_MTXM_TAIL, lab.RECT_LAYER_TAIL_ORIGINAL, "MTXM tail"),
        (lab.RVA_RECT_SQM_TAIL, lab.RECT_LAYER_TAIL_ORIGINAL, "SQM tail"),
        (lab.RVA_RECT_REGM_TAIL, lab.RECT_LAYER_TAIL_ORIGINAL, "REGM tail"),
    ]
    for rva, expected, name in hook_sites:
        actual = read_rva(raw, rva, len(expected))
        if actual != expected:
            raise AssertionError(
                f"{name} mismatch at RVA 0x{rva:06X}: "
                f"expected {expected.hex(' ')}, found {actual.hex(' ')}"
            )
        checked += 1

    stock_nav_va = 0x00400000 + lab.RVA_NAV_BLOCK_BUFFER
    for rva in lab.NAV_BLOCK_BUFFER_XREF_RVAS:
        actual = struct.unpack("<I", read_rva(raw, rva, 4))[0]
        if actual != stock_nav_va:
            raise AssertionError(
                f"navigation xref RVA 0x{rva:06X}: expected 0x{stock_nav_va:08X}, "
                f"found 0x{actual:08X}"
            )
        checked += 1

    for rva, expected, _entry, _length, name in lab.RECT_MINIMAP_HOOK_SITES:
        actual = read_rva(raw, rva, len(expected))
        if actual != expected:
            raise AssertionError(
                f"{name} mismatch at RVA 0x{rva:06X}: "
                f"expected {expected.hex(' ')}, found {actual.hex(' ')}"
            )
        checked += 1

    for rva, _entry, name in lab.RECT_SCROLL_HOOK_SITES:
        expected = lab._rect_scroll_original(0x00400000, rva)
        actual = read_rva(raw, rva, len(expected))
        if actual != expected:
            raise AssertionError(
                f"{name} mismatch at RVA 0x{rva:06X}: "
                f"expected {expected.hex(' ')}, found {actual.hex(' ')}"
            )
        checked += 1

    for base in (0x00400000, 0x00790000, 0x00C10000):
        auto_cave = lab.build_auto_rectangle_cave(base, 0x03000000)
        marker = auto_cave[
            lab.AUTO_RECT_MARKER_OFFSET:
            lab.AUTO_RECT_MARKER_OFFSET + len(lab.AUTO_RECT_MARKER)
        ]
        if marker != lab.AUTO_RECT_MARKER:
            raise AssertionError(f"auto cave marker mismatch for base 0x{base:08X}")
        mini_cave = lab.build_rect_minimap_cave(base, 0x03000000, 0x03100000)
        marker = mini_cave[
            lab.RECT_MINIMAP_ENTRY_OFFSETS['marker']:
            lab.RECT_MINIMAP_ENTRY_OFFSETS['marker'] + len(lab.RECT_MINIMAP_MARKER)
        ]
        if marker != lab.RECT_MINIMAP_MARKER:
            raise AssertionError(f"minimap cave marker mismatch for base 0x{base:08X}")
        if mini_cave[lab.RECT_MINIMAP_STATE_READY] != 0:
            raise AssertionError(f"minimap cave is not square-safe at base 0x{base:08X}")
        scroll_cave = lab.build_rect_scroll_cave(base, 0x03000000, 0x03200000)
        marker = scroll_cave[
            lab.RECT_SCROLL_ENTRY_OFFSETS['marker']:
            lab.RECT_SCROLL_ENTRY_OFFSETS['marker'] + len(lab.RECT_SCROLL_MARKER)
        ]
        if marker != lab.RECT_SCROLL_MARKER:
            raise AssertionError(f"scroll cave marker mismatch for base 0x{base:08X}")
        checked += 3

    sizes = lab.exhaustive_dimension_self_test()
    return [
        f"Executable: {exe_path}",
        f"SHA-256: {digest}",
        f"Static sites verified: {checked}",
        f"Patch records: {len(lab.PATCHES)}",
        f"Dimension combinations: {sizes['combinations']}",
        f"Storage stride buckets: {sizes['stride_buckets']}",
        "RESULT: PASS",
    ]


def main() -> int:
    if len(sys.argv) <= 1:
        sizes = lab.exhaustive_dimension_self_test()
        for base in (0x00400000, 0x00790000, 0x00C10000):
            assert lab.AUTO_RECT_MARKER in lab.build_auto_rectangle_cave(base, 0x03000000)
        print(f"Offline static checks: PASS ({sizes['combinations']} dimension combinations)")
        print("For exact executable-byte verification: py static_verify.py <path-to-your-Warcraft-II.exe>")
        return 0
    path = Path(sys.argv[1])
    for line in verify(path):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
