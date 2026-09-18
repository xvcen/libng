import sys, os, struct, json, re
sys.path.insert(0, '/home/user/libng/analysis')
from emu_jni import JniEmu
from emu import dump_memory
from unicorn import *
from unicorn.arm64_const import *

def init_funcs(emu):
    ia = emu.e.sections['.init_array']; rel = emu.e.sections['.rela.dyn']; d = emu.e.data
    out = []
    for i in range(rel['size'] // 24):
        off, info, add = struct.unpack_from('<QQq', d, rel['offset'] + i * 24)
        if (info & 0xffffffff) == 1027 and ia['addr'] <= off < ia['addr'] + ia['size']:
            out.append(((off - ia['addr']) // 8, add))
    out.sort()
    return out

def main():
    emu = JniEmu()
    fns = init_funcs(emu)
    print('constructors:', len(fns))
    ok = fail = 0
    for idx, fn in fns:
        emu.halted = None
        emu.log.clear()
        r = emu.call(fn, count=5_000_000)
        if emu.halted:
            fail += 1
            print(f'  init[{idx}] @0x{fn:x} FAILED: {emu.halted}')
        else:
            ok += 1
    print(f'constructors ok={ok} failed={fail}')
    print('imports used so far:', dict(emu.calls))
    if emu.props:
        print('properties queried during init:', sorted(set(emu.props)))
    # JNI_OnLoad
    addr = [s for s in emu.e.syms if s['name'] == 'JNI_OnLoad'][0]['value']
    emu.halted = None; emu.log.clear()
    r = emu.call(addr, (emu.vm, 0), count=20_000_000)
    print('JNI_OnLoad ->', r, 'halted:', emu.halted)
    print('imports:', dict(emu.calls))
    print('properties:', sorted(set(emu.props)))
    for e in emu.jni_log[:60]:
        print('   JNI:', e)
    dump_memory(emu, '/home/user/libng/analysis/out/mem2')
    json.dump(emu.jni_log, open('/home/user/libng/analysis/out/jni_log.json', 'w'), indent=1)

if __name__ == '__main__':
    main()
