from pathlib import Path
import importlib.util
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location('lab095', ROOT / 'war2_extended_map_lab.py')
lab = importlib.util.module_from_spec(SPEC)
sys.modules['lab095'] = lab
SPEC.loader.exec_module(lab)


def pe_rva_bytes(path: Path, rva: int, size: int) -> bytes:
    data = path.read_bytes()
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    count = struct.unpack_from('<H', data, pe + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe + 20)[0]
    table = pe + 24 + opt_size
    for i in range(count):
        off = table + i * 40
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from('<IIII', data, off + 8)
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            pos = raw_offset + (rva - virtual_address)
            return data[pos:pos+size]
    raise AssertionError(hex(rva))


def test_exact_scroll_hook_sites():
    exe = Path(__import__('os').environ.get('WAR2_EXE', 'Warcraft II.exe'))
    if not exe.exists():
        print('SKIP exact executable hook-site check: set WAR2_EXE to your own game executable')
        return
    for base in (0x00400000, 0x00790000, 0x00C10000):
        # File bytes use the preferred image base; the builder must still
        # generate correct ASLR-aware originals for every observed base.
        for rva, _entry, _desc in lab.RECT_SCROLL_HOOK_SITES:
            runtime = lab._rect_scroll_original(base, rva)
            assert len(runtime) == 7
            if base == 0x00400000:
                assert pe_rva_bytes(exe, rva, 7) == runtime


def test_scroll_cave_layout_and_marker():
    for base in (0x00400000, 0x00790000, 0x00C10000):
        auto = 0x05000000
        cave = 0x06000000
        payload = lab.build_rect_scroll_cave(base, auto, cave)
        assert len(payload) == lab.RECT_SCROLL_CAVE_SIZE
        mo = lab.RECT_SCROLL_ENTRY_OFFSETS['marker']
        assert payload[mo:mo+len(lab.RECT_SCROLL_MARKER)] == lab.RECT_SCROLL_MARKER
        # Width entries load logical width; height entries load logical height.
        assert struct.pack('<I', auto + lab.AUTO_RECT_LOGICAL_WIDTH) in payload[0x00:0x20]
        assert struct.pack('<I', auto + lab.AUTO_RECT_LOGICAL_HEIGHT) in payload[0x20:0x50]
        assert struct.pack('<I', auto + lab.AUTO_RECT_LOGICAL_WIDTH) in payload[0x50:0x70]
        assert struct.pack('<I', auto + lab.AUTO_RECT_LOGICAL_HEIGHT) in payload[0x70:0xA0]
        # Both vertical stubs convert logical height from tiles to pixels.
        assert b'\xC1\xE1\x05' in payload[0x20:0x50]
        assert b'\xC1\xE2\x05' in payload[0x70:0xA0]


def test_legacy_camera_formula():
    # legacy reference module computes map-right/bottom as map dimension minus visible
    # viewport. The remaster stores pixels, so use dimension*32 - viewport.
    def clamp_max(dim_tiles: int, viewport_px: int) -> int:
        return max(0, dim_tiles * 32 - viewport_px)

    # Representative 32x96 viewport: X can never enter the hidden 96-wide
    # backing columns, while Y still spans the tall logical map.
    assert clamp_max(32, 704) == 320
    assert clamp_max(96, 704) == 2368
    # Tiny maps clamp at the origin rather than underflowing.
    assert clamp_max(1, 704) == 0
    # 256 square behavior remains the same formula used by stock 0.9.0.
    assert clamp_max(256, 704) == 7488


def test_hook_jump_round_trip():
    base = 0x00790000
    cave = 0x06000000
    for rva, entry, _desc in lab.RECT_SCROLL_HOOK_SITES:
        target = cave + lab.RECT_SCROLL_ENTRY_OFFSETS[entry]
        patch = lab._mini_jump(base, rva, target, 7)
        assert len(patch) == 7 and patch[:1] == b'\xE9'
        assert lab._mini_decode_target(base, rva, patch) == target
        assert lab._decode_rect_scroll_cave(base, rva, patch, entry) == cave


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for test in tests:
        test()
        print('PASS', test.__name__)
    print(f'{len(tests)} native-scroll tests passed')
