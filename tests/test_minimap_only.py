from pathlib import Path
import importlib.util
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location('lab', ROOT / 'war2_extended_map_lab.py')
lab = importlib.util.module_from_spec(SPEC)
sys.modules['lab'] = lab
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


def test_exact_hook_sites():
    exe = Path(__import__('os').environ.get('WAR2_EXE', 'Warcraft II.exe'))
    if not exe.exists():
        print('SKIP exact executable hook-site check: set WAR2_EXE to your own game executable')
        return
    for rva, original, _entry, _length, _desc in lab.RECT_MINIMAP_HOOK_SITES:
        assert pe_rva_bytes(exe, rva, len(original)) == original


def test_cave_template():
    payload = lab.build_rect_minimap_cave(0x00790000, 0x039A0000, 0x039B0000)
    marker = lab.RECT_MINIMAP_ENTRY_OFFSETS['marker']
    assert payload[marker:marker+len(lab.RECT_MINIMAP_MARKER)] == lab.RECT_MINIMAP_MARKER
    for sentinel in [0x11111111,0x22222222,0x33333333,0x44444444,0x44444446,
                     0x55555555,0x66666666,0x77777777,0x90909090,0x94949494,
                     0x98989898,0x9C9C9C9C,0xA1A1A1A1,0xA2A2A2A2,0xA3A3A3A3,
                     0xA4A4A4A4,0xA5A5A5A5,0xA6A6A6A6,0xA7A7A7A7,
                     0xB1B1B1B1,0xB2B2B2B2,0xB3B3B3B3,0xB4B4B4B4,
                     0xC5C5C5C5,0xC6C6C6C6,0xC7C7C7C7,0xC8C8C8C8,
                     0xD1D1D1D1,0xD2D2D2D2,0xD3D3D3D3,0xD4D4D4D4,
                     0xAAAAAAAA,0xBBBBBBBB,0xEEEEEEEE,0xEFEFEFEF,
                     0xF0F0F0F0,0xF1F1F1F1]:
        assert struct.pack('<I', sentinel) not in payload
    # Cave state begins zeroed, so square maps and pre-load menus bypass swaps.
    assert payload[lab.RECT_MINIMAP_STATE_READY] == 0


def test_resample_32x96_uses_native_96_raster_without_padding():
    width, height, stride = 32, 96, 96
    target = lab.rect_minimap_raster_side(stride)
    assert target == 96
    cells = stride * stride
    terrain = bytearray(cells * 2)
    gray = bytearray([0xEE]) * cells
    local = bytearray([0xDD]) * cells
    for y in range(height):
        for x in range(width):
            off = y * stride + x
            struct.pack_into('<H', terrain, off * 2, (y * width + x) & 0xFFFF)
            gray[off] = (x + y) & 0xFF
            local[off] = (x * 3 + y * 5) & 0xFF
    out_t, out_g, out_l = lab._resample_rect_minimap(
        bytes(terrain), bytes(gray), bytes(local), width, height, stride, target
    )
    assert len(out_t) == target*target*2
    assert len(out_g) == target*target
    assert len(out_l) == target*target
    # Corners and center map to valid logical cells, never padding sentinels.
    for dx, dy in [(0,0),(target-1,0),(0,target-1),(target-1,target-1),(target//2,target//2)]:
        dest = dy*target+dx
        sx = min(width-1, ((2*dx+1)*width)//(2*target))
        sy = min(height-1, ((2*dy+1)*height)//(2*target))
        src = sy*stride+sx
        assert struct.unpack_from('<H', out_t, dest*2)[0] == struct.unpack_from('<H', terrain, src*2)[0]
        assert out_g[dest] == gray[src] and out_g[dest] != 0xEE
        assert out_l[dest] == local[src] and out_l[dest] != 0xDD

    # The 32 logical columns occupy the 96-cell native raster evenly: exactly
    # three raster columns per source column before Warcraft's final scaler.
    first_row = [struct.unpack_from('<H', out_t, x*2)[0] for x in range(target)]
    for source_x in range(width):
        assert first_row[source_x*3:(source_x+1)*3] == [source_x] * 3


def test_resample_all_representative_rectangles():
    for width, height in [(1,2),(2,1),(5,9),(9,5),(32,96),(96,32),(127,255),(255,127)]:
        stride = lab.dimension_plan(width,height).stride
        target = lab.rect_minimap_raster_side(stride)
        cells = stride*stride
        terrain = bytes(cells*2)
        gray = bytes(cells)
        local = bytes(cells)
        outputs = lab._resample_rect_minimap(terrain,gray,local,width,height,stride,target)
        assert [len(x) for x in outputs] == [target*target*2,target*target,target*target]


def test_native_raster_side_buckets():
    assert lab.rect_minimap_raster_side(1) == 32
    assert lab.rect_minimap_raster_side(32) == 32
    assert lab.rect_minimap_raster_side(33) == 64
    assert lab.rect_minimap_raster_side(64) == 64
    assert lab.rect_minimap_raster_side(65) == 96
    assert lab.rect_minimap_raster_side(96) == 96
    assert lab.rect_minimap_raster_side(97) == 128
    assert lab.rect_minimap_raster_side(256) == 128


def test_crash23_opcode_safe_relocations():
    cave = 0x06540000
    payload = lab.build_rect_minimap_cave(0x00790000, 0x05960000, cave)

    # Crash 23 occurred because repeated A1/A3 placeholder bytes were replaced
    # with overlapping matches, overwriting the x86 MOV opcodes at these four
    # locations. The opcode and exact state-address immediate must survive.
    expected = {
        0x359: cave + lab.RECT_MINIMAP_STATE_TERRAIN_PTR,
        0x36D: cave + lab.RECT_MINIMAP_STATE_LOCAL_PTR,
        0x403: cave + lab.RECT_MINIMAP_STATE_TERRAIN_PTR,
        0x417: cave + lab.RECT_MINIMAP_STATE_LOCAL_PTR,
    }
    for offset, address in expected.items():
        assert payload[offset] == 0xA1
        assert struct.unpack_from('<I', payload, offset + 1)[0] == address

    # The following A3 stores must also remain intact; old overlapping
    # replacement corrupted these opcodes after the A3A3A3A3 immediates.
    assert payload[0x372] == 0xA3
    assert payload[0x41C] == 0xA3


if __name__ == '__main__':
    tests=[v for k,v in sorted(globals().items()) if k.startswith('test_')]
    for test in tests:
        test(); print('PASS',test.__name__)
    print(f'{len(tests)} minimap-only tests passed')
