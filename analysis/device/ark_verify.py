"""Verify the .ark integrity-checksum table of libng.so.

Model (verified for the 14,535 simple records):
    struct ArkRecord { u64 checksum; u64 len; u64 off; u64 extra_len; }
    target = (blob + delta) ^ checksum ^ fnv_ror_hash(blob, len)
For unmodified code: fnv_ror_hash == checksum  =>  target == blob + delta
=> any patch/hook changes the hash and thus poisons the computed jump target.
"""
import sys, struct, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF

M = (1 << 64) - 1
FNV_BASIS = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3

def ror(x, n):
    return ((x >> n) | (x << (64 - n))) & M

def fnv_ror(blob, x9=FNV_BASIS):
    n = len(blob) & ~7
    for off in range(0, n, 8):
        x9 = ror(((x9 ^ struct.unpack_from('<Q', blob, off)[0]) * FNV_PRIME) & M, 37)
    if len(blob) != n:
        x9 = ror(((x9 ^ struct.unpack_from('<Q', blob, len(blob) - 8)[0]) * FNV_PRIME) & M, 37)
    return x9

def main(path='/home/user/libng/libng.so'):
    e = ELF(path); d = e.data
    ark = e.sections['.ark']
    n = ark['size'] // 32
    ok = single = 0
    for i in range(n):
        va = ark['addr'] + i * 32
        checksum, ln, off, extra = struct.unpack_from('<QQQQ', d, e.va2off(va))
        if extra == 0:
            single += 1
        blob = e.read_va(va + off, ln)
        if blob and len(blob) == ln and fnv_ror(blob) == checksum:
            ok += 1
    print(f'libng.so: {n} .ark records; {single} single-block; {ok} verified single-block checksums')
    return ok

if __name__ == '__main__':
    main(*sys.argv[1:])
