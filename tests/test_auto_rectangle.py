from __future__ import annotations

import base64
from pathlib import Path
import sys
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import war2_extended_map_lab as lab

RAW_MAP = ROOT / "maps" / "32x96_raw_test.pud"


def parse(path: Path) -> dict[bytes, bytes]:
    raw = path.read_bytes()
    out: dict[bytes, bytes] = {}
    off = 0
    while off < len(raw):
        tag = raw[off:off + 4]
        size = struct.unpack_from("<I", raw, off + 4)[0]
        out[tag] = raw[off + 8:off + 8 + size]
        off += 8 + size
    return out


def unpack_words(data: bytes) -> list[int]:
    return list(struct.unpack(f"<{len(data) // 2}H", data))


def expand(values: list[int], width: int, height: int, side: int, pad: int | None) -> list[int]:
    output = [0] * (side * side)
    for y in range(side):
        for x in range(side):
            if x < width and y < height:
                output[y * side + x] = values[y * width + x]
            elif y < height and pad is None:
                output[y * side + x] = values[y * width + width - 1]
            elif pad is None:
                output[y * side + x] = output[(height - 1) * side + min(x, width - 1)]
            else:
                output[y * side + x] = pad
    return output


def call_target(raw: bytes, call_offset: int) -> int:
    assert raw[call_offset] == 0xE8
    disp = struct.unpack_from("<i", raw, call_offset + 1)[0]
    return call_offset + 5 + disp


class AutoRectangleTests(unittest.TestCase):
    def test_raw_32x96_dimensions_and_chunks(self) -> None:
        chunks = parse(RAW_MAP)
        self.assertEqual(struct.unpack("<HH", chunks[b"DIM "]), (32, 96))
        for tag in (b"MTXM", b"SQM ", b"REGM"):
            self.assertEqual(len(chunks[tag]), 32 * 96 * 2)

    def test_parser_time_expansion_preserves_every_authored_row(self) -> None:
        chunks = parse(RAW_MAP)
        width, height = struct.unpack("<HH", chunks[b"DIM "])
        side = 96
        pads = {b"MTXM": None, b"SQM ": 0x0081, b"REGM": 0xFFFD}
        for tag, pad in pads.items():
            source = unpack_words(chunks[tag])
            grid = expand(source, width, height, side, pad)
            self.assertEqual(len(grid), side * side)
            for y in range(height):
                self.assertEqual(
                    grid[y * side:y * side + width],
                    source[y * width:(y + 1) * width],
                    f"{tag!r} row {y} changed during expansion",
                )
            self.assertEqual(grid[95 * side + 31], source[95 * width + 31])

    def test_dimension_rounding(self) -> None:
        cases = {
            (1, 1): 32, (2, 2): 32, (5, 9): 32,
            (32, 96): 96, (96, 32): 96, (33, 65): 96,
            (127, 255): 256, (256, 256): 256,
        }
        for (width, height), expected in cases.items():
            side = (max(32, width, height) + 31) & ~31
            self.assertEqual(side, expected)

    def test_cave_uses_parser_tail_entries(self) -> None:
        raw = base64.b64decode(lab.AUTO_RECT_TEMPLATE_B64)
        self.assertEqual(
            raw[lab.AUTO_RECT_MARKER_OFFSET:lab.AUTO_RECT_MARKER_OFFSET + len(lab.AUTO_RECT_MARKER)],
            lab.AUTO_RECT_MARKER,
        )
        self.assertEqual(raw[lab.AUTO_RECT_SCENARIO_ENTRY], 0x9C)
        self.assertEqual(raw[lab.AUTO_RECT_DIM_ENTRY], 0x55)
        for entry in (lab.AUTO_RECT_MTXM_ENTRY, lab.AUTO_RECT_SQM_ENTRY, lab.AUTO_RECT_REGM_ENTRY):
            self.assertEqual(raw[entry:entry + 3], bytes.fromhex("83 c4 08"))
        self.assertEqual(call_target(raw, lab.AUTO_RECT_MTXM_ENTRY + 0x43), 0x600)
        self.assertEqual(call_target(raw, lab.AUTO_RECT_SQM_ENTRY + 0x46), 0x600)
        self.assertEqual(call_target(raw, lab.AUTO_RECT_REGM_ENTRY + 0x46), 0x600)

    def test_runtime_relocation_and_sentinel_resolution(self) -> None:
        sentinels = (0x99999999, 0xBBBBBBBB, 0x33333333, 0x11111111,
                     0x12121212, 0x22222222, 0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF)
        for base in (0x00400000, 0x00790000, 0x00C10000):
            cave = lab.build_auto_rectangle_cave(base, 0x03000000)
            self.assertEqual(
                cave[lab.AUTO_RECT_MARKER_OFFSET:lab.AUTO_RECT_MARKER_OFFSET + len(lab.AUTO_RECT_MARKER)],
                lab.AUTO_RECT_MARKER,
            )
            for sentinel in sentinels:
                self.assertNotIn(struct.pack("<I", sentinel), cave)

    def test_dynamic_site_partition(self) -> None:
        self.assertEqual(len(lab.DYNAMIC_BYTE_HOOK_RVAS), 15)
        self.assertIn(0x0C6548, lab.DYNAMIC_BYTE_HOOK_RVAS)
        self.assertEqual(len(lab.DYNAMIC_WORD_SIZE_RVAS), 9)
        self.assertEqual(len(lab.DYNAMIC_DWORD_SIZE_RVAS), 8)

    def test_padding_geometry_for_32x96(self) -> None:
        width, height, side = 32, 96, 96
        real = bytearray([0] * (side * side))
        for y in range(side):
            x0 = width if y < height else 0
            for x in range(x0, side):
                real[y * side + x] = lab.H_ALL
        self.assertEqual(sum(v == lab.H_ALL for v in real), (side - width) * height)
        self.assertTrue(all(real[y * side + x] == 0 for y in range(height) for x in range(width)))

    def test_padding_geometry_for_short_map(self) -> None:
        width, height, side = 96, 32, 96
        padding = set()
        for y in range(side):
            x0 = width if y < height else 0
            padding.update(range(y * side + x0, (y + 1) * side))
        self.assertEqual(len(padding), width * (side - height))
        self.assertNotIn(0, padding)
        self.assertIn(32 * side, padding)

    def test_mask_helper_preserves_authored_rectangle(self) -> None:
        side, width, height = 6, 2, 4
        memory = bytearray(range(side * side))
        original = bytes(memory)
        writes: list[bytes] = []
        old_read = lab.read_memory
        old_write = lab.write_data
        try:
            lab.read_memory = lambda _k, _p, _a, size: bytes(memory[:size])
            def fake_write(_k, _p, _a, payload):
                writes.append(bytes(payload))
                memory[:] = payload
            lab.write_data = fake_write
            changed = lab._mask_padding_in_buffer(None, None, 0x1000, width, height, side, 0x10)
        finally:
            lab.read_memory = old_read
            lab.write_data = old_write
        self.assertTrue(changed)
        self.assertEqual(len(writes), 1)
        for y in range(height):
            self.assertEqual(memory[y * side:y * side + width], original[y * side:y * side + width])
            self.assertEqual(memory[y * side + width:(y + 1) * side], bytes([0x10]) * (side - width))
        self.assertEqual(memory[height * side:], bytes([0x10]) * ((side - height) * side))

    def test_mask_helper_skips_write_when_padding_is_already_correct(self) -> None:
        side, width, height = 4, 2, 4
        memory = bytearray([0] * (side * side))
        for y in range(height):
            memory[y * side + width:(y + 1) * side] = bytes([0x10]) * (side - width)
        writes = []
        old_read = lab.read_memory
        old_write = lab.write_data
        try:
            lab.read_memory = lambda _k, _p, _a, size: bytes(memory[:size])
            lab.write_data = lambda *_args: writes.append(True)
            changed = lab._mask_padding_in_buffer(None, None, 0x1000, width, height, side, 0x10)
        finally:
            lab.read_memory = old_read
            lab.write_data = old_write
        self.assertFalse(changed)
        self.assertEqual(writes, [])

    def test_all_65536_dimension_pairs(self) -> None:
        result = lab.exhaustive_dimension_self_test()
        self.assertEqual(result["combinations"], 65536)
        self.assertEqual(result["stride_buckets"], 8)

    def test_dimension_plan_representative_pairs(self) -> None:
        expected = {
            (1, 1): (32, 1, 1024),
            (2, 2): (32, 4, 1024),
            (5, 9): (32, 45, 1024),
            (32, 96): (96, 3072, 9216),
            (96, 32): (96, 3072, 9216),
            (127, 255): (256, 32385, 65536),
            (255, 127): (256, 32385, 65536),
            (256, 256): (256, 65536, 65536),
        }
        for dims, values in expected.items():
            plan = lab.dimension_plan(*dims)
            self.assertEqual((plan.stride, plan.compact_cells, plan.storage_cells), values)

    def test_dimension_plan_rejects_out_of_range(self) -> None:
        for dims in ((0, 1), (1, 0), (257, 1), (1, 257), (-1, 32)):
            with self.assertRaises(ValueError):
                lab.dimension_plan(*dims)

    def test_word_padding_helper(self) -> None:
        side, width, height = 4, 2, 3
        words = list(range(side * side))
        memory = bytearray(struct.pack(f"<{len(words)}H", *words))
        old_read = lab.read_memory
        old_write = lab.write_data
        writes = []
        try:
            lab.read_memory = lambda _k, _p, _a, size: bytes(memory[:size])
            def fake_write(_k, _p, _a, payload):
                writes.append(True)
                memory[:] = payload
            lab.write_data = fake_write
            changed = lab._mask_padding_in_word_buffer(
                None, None, 0x2000, width, height, side, 0xFFFD
            )
        finally:
            lab.read_memory = old_read
            lab.write_data = old_write
        self.assertTrue(changed)
        self.assertEqual(writes, [True])
        result = list(struct.unpack(f"<{side * side}H", memory))
        for y in range(height):
            self.assertEqual(result[y * side:y * side + width], words[y * side:y * side + width])
            self.assertEqual(result[y * side + width:(y + 1) * side], [0xFFFD] * (side - width))
        self.assertEqual(result[height * side:], [0xFFFD] * ((side - height) * side))


if __name__ == "__main__":
    unittest.main()
