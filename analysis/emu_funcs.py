"""Run exported functions under emulation and diff-scan memory for decrypted strings."""
import sys, os, struct, re, json
sys.path.insert(0, '/home/user/libng/analysis')
from emu_jni import JniEmu
from emu_run import init_funcs
from unicorn import *
from unicorn.arm64_const import *

EXPORTS = ['register_callback', 'get_heartbeat_data', 'set_player_token', 'is_emulator', 'ng_ioctl', 'JNI_OnLoad']

def file_strings(emu):
    out = set()
    for m in re.finditer(rb'[\x20-\x7e]{4,}', emu.e.data):
        out.add(m.group())
    return out

def scan_strings(emu, minlen=5):
    """scan all mapped memory (from segment list + heap/stack) for printable strings"""
    res = {}
    regions = []
    d = emu.e.data
    e_phoff, = struct.unpack_from('<Q', d, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        t, fl, po, pv, pa, fs, ms, al = struct.unpack_from('<IIQQQQQQ', d, off)
        if t == 1:
            regions.append((pv, ms))
    regions.append((emu.heap_ptr - 0x200000 if emu.heap_ptr > 0x200000 else 0x600000000, 0x200000))
    regions.append((0x700000000, 0x400000))
    for base, size in regions:
        try:
            blob = bytes(emu.uc.mem_read(base, size))
        except UcError:
            continue
        for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minlen, blob):
            s = m.group()
            res.setdefault(s, []).append(base + m.start())
    return res

def main():
    emu = JniEmu()
    for idx, fn in init_funcs(emu):
        emu.halted = None; emu.call(fn, count=5_000_000)
    fs = file_strings(emu)
    results = {}
    for name in EXPORTS:
        sym = [s for s in emu.e.syms if s['name'] == name][0]
        before = scan_strings(emu) if False else None
        emu.props.clear(); emu.jni_log.clear(); emu.calls.clear()
        args = {'register_callback': (0x1000, 0x1000),
                'get_heartbeat_data': (0x2000, 0x1000, 0x1000),
                'set_player_token': (0x3000, 0x40),
                'is_emulator': (),
                'ng_ioctl': (1, 0, 0, 0),
                'JNI_OnLoad': (emu.vm, 0)}[name]
        emu.halted = None
        r = emu.call(sym['value'], args, count=20_000_000)
        mem = scan_strings(emu)
        new = sorted({s for s, addrs in mem.items() if s not in fs and len(s) >= 6}, key=len, reverse=True)
        # only strings that are NOT in the current file bytes (i.e., produced at runtime)
        results[name] = {'ret': r if r is None or r < 2**63 else r - 2**64, 'halted': emu.halted,
                         'props': sorted(set(emu.props)), 'imports': dict(emu.calls),
                         'jni': emu.jni_log[:40], 'new_strings': [s.decode('latin1') for s in new[:200]]}
        print(f'=== {name}: ret={results[name]["ret"]} halted={emu.halted}')
        print('    props:', results[name]['props'][:20])
        print('    imports:', results[name]['imports'])
        if emu.jni_log:
            print('    jni:', emu.jni_log[:6])
        print('    new strings sample:', [s.decode("latin1") for s in new[:25]])
    json.dump(results, open('/home/user/libng/analysis/out/funcs.json', 'w'), indent=1)

main()
