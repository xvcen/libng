"""
Unicorn-based loader/emulator for libng.so (AArch64 Android .so).

Purpose: run the library's constructors / JNI_OnLoad in a sandbox to observe
runtime decryption of obfuscated tables (Arkari) and dump plaintext data.

The library is position independent; we map it at address 0 so that
file offset == virtual address for the first LOAD segment.
"""
import sys, struct, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from elf import ELF
from unicorn import *
from unicorn.arm64_const import *

PATH = os.environ.get('LIBNG', '/home/user/libng/libng.so')

STUB_BASE = 0x50000000          # import thunks
HEAP_BASE = 0x600000000         # bump heap
HEAP_SIZE = 64 * 1024 * 1024
STACK_BASE = 0x700000000
STACK_SIZE = 4 * 1024 * 1024


class Emu:
    def __init__(self, path=PATH, trace=False):
        self.e = ELF(path)
        self.trace = trace
        self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.imports = {}        # addr -> name
        self.import_names = set()
        self.heap_ptr = HEAP_BASE
        self.calls = collections.Counter()
        self.log = []
        self.halted = None
        self._load()

    # ---------------- loading ----------------
    def _load(self):
        uc = self.uc
        e = self.e
        d = e.data
        # map by program headers
        e_phoff, = struct.unpack_from('<Q', d, 0x20)
        e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
        segs = []
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from('<IIQQQQQQ', d, off)
            if p_type != 1:  # PT_LOAD
                continue
            segs.append((p_vaddr, p_memsz, p_offset, p_filesz))
            page = p_vaddr & ~0xfff
            end = (p_vaddr + p_memsz + 0xfff) & ~0xfff
            uc.mem_map(page, end - page)
            uc.mem_write(p_vaddr, d[p_offset:p_offset + p_filesz])
        # stack
        uc.mem_map(STACK_BASE, STACK_SIZE)
        uc.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x1000)
        # heap
        uc.mem_map(HEAP_BASE, HEAP_SIZE)
        # stub region: one 4-byte slot per import
        self.import_addrs = []
        names = []
        for s in e.syms:
            if s['shndx'] == 0 and s['name']:
                names.append(s['name'])
                self.import_names.add(s['name'])
        for i, nm in enumerate(names):
            self.import_addrs.append(STUB_BASE + i * 8)
            self.imports[STUB_BASE + i * 8] = nm
        uc.mem_map(STUB_BASE, ((len(names) * 8) + 0xfff) & ~0xfff)
        # trampoline page used as fake return address
        self.ret_addr = STUB_BASE - 0x1000
        uc.mem_map(self.ret_addr & ~0xfff, 0x1000)
        uc.mem_write(self.ret_addr, b'\xc0\x03\x5f\xd6' * 64)
        self.sym_by_name = {s['name']: s for s in e.syms}
        self.import_idx = {nm: i for i, nm in enumerate(names)}
        self._relocate()
        uc.hook_add(UC_HOOK_CODE, self._hook_code)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._hook_unmapped)
        uc.hook_add(UC_HOOK_MEM_INVALID, self._hook_unmapped)

    def _relocate(self):
        uc, e, d = self.uc, self.e, self.e.data
        rel = e.sections['.rela.dyn']
        self.globals = {}
        for i in range(rel['size'] // 24):
            off, info, add = struct.unpack_from('<QQq', d, rel['offset'] + i * 24)
            t = info & 0xffffffff
            symi = info >> 32
            if t == 1027:      # R_AARCH64_RELATIVE
                uc.mem_write(off, struct.pack('<Q', add & 0xffffffffffffffff))
            elif t in (1025, 257):  # GLOB_DAT / ABS64
                nm = e.syms[symi]['name'] if symi < len(e.syms) else ''
                if nm in self.import_idx:
                    if t == 1025:
                        uc.mem_write(off, struct.pack('<Q', self.import_addrs[self.import_idx[nm]]))
                    else:
                        self.globals[off] = nm

    # ---------------- hooks ----------------
    def _hook_code(self, uc, address, size, user):
        if address == self.ret_addr:
            self.uc.emu_stop()
            return
        if address in self.imports:
            self._do_import(self.imports[address])
            return
        if self.trace:
            print(f'  {address:08x}')

    def _hook_unmapped(self, uc, access, address, size, value, user):
        self.halt(f'unmapped {access} at 0x{address:x} size {size} value 0x{value:x}')
        return False

    def halt(self, why):
        if self.halted is None:
            self.halted = why
        self.uc.emu_stop()

    # ---------------- import implementations ----------------
    def _ret(self, val=0):
        uc = self.uc
        lr = uc.reg_read(UC_ARM64_REG_LR)
        uc.reg_write(UC_ARM64_REG_X0, val & 0xffffffffffffffff)
        uc.reg_write(UC_ARM64_REG_PC, lr)

    def alloc(self, n, align=16):
        n = (n + 15) & ~15
        p = self.heap_ptr
        self.heap_ptr = (self.heap_ptr + n + align) & ~(align - 1)
        if self.heap_ptr >= HEAP_BASE + HEAP_SIZE:
            raise RuntimeError('heap exhausted')
        return p

    def rd(self, reg):
        return self.uc.reg_read(reg)

    def rds(self, va, n):
        return self.uc.mem_read(va, n)

    def cstr(self, va, n=256):
        try:
            b = self.uc.mem_read(va, n)
        except UcError:
            return None
        z = b.find(b'\0')
        return bytes(b[:z]) if z >= 0 else bytes(b)

    def _do_import(self, name):
        uc = self.uc
        self.calls[name] += 1
        args = [self.rd(UC_ARM64_REG_X0), self.rd(UC_ARM64_REG_X1), self.rd(UC_ARM64_REG_X2), self.rd(UC_ARM64_REG_X3)]
        log = f'IMPORT {name}({", ".join(hex(a) for a in args)})'
        if len(self.log) < 4000:
            self.log.append(log)
        # --- memory management ---
        if name in ('_Znwm', '_Znam'):
            self._ret(self.alloc(args[0] if args[0] else 1))
            return
        if name in ('_ZdlPv', '_ZdaPv', 'free', '_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED2Ev'):
            # operator delete / free / string dtor: nothing to do
            if name.endswith('D2Ev'):
                self._destroy_string(args[0])
            self._ret(0)
            return
        if name == '__stack_chk_fail':
            self.halt('__stack_chk_fail')
            return
        if name in ('__cxa_guard_acquire',):
            # guard is a pointer to 8-byte value; return 1 = acquire (caller runs init)
            self._ret(1)
            return
        if name in ('__cxa_guard_release',):
            self.uc.mem_write(args[0], struct.pack('<Q', 1))
            self._ret(0)
            return
        if name in ('__cxa_atexit', '__register_atfork'):
            self._ret(0)
            return
        if name == '__system_property_get':
            # return 0 (not found); property buffer may be left untouched
            self._ret(0)
            return
        if name == 'sysconf':
            self._ret(4096)
            return
        if name == 'getauxval':
            self._ret(0)
            return
        if name == 'dl_iterate_phdr':
            self._ret(0)
            return
        if name in ('dlsym', 'dlopen', 'dlclose'):
            self._ret(0)
            return
        if name.startswith('shadowhook'):
            self._ret(0 if 'init' in name else -1)
            return
        if name == '__emutls_get_address':
            self._ret(self.alloc(64))
            return
        if 'steady_clock3nowEv' in name:
            self._ret(0x1000000)
            return
        if 'to_string' in name:
            self._ret(self._mk_string(str(args[0]).encode()))
            return
        if name.startswith('_ZNSt6__ndk112basic_string'):
            self._string_op(name, args)
            return
        if name == '_ZNSt6__ndk1plIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_12basic_stringIT_T0_T1_EEPKS6_RKS9_':
            # operator+(const char*, const string&)
            lhs = self.cstr(args[0]) or b''
            rhs = self._string_data(args[1])
            self._ret(self._mk_string(lhs + rhs))
            return
        if name in ('_ZNSt6__ndk118condition_variableD1Ev', '_ZNSt6__ndk15mutexD1Ev', '_ZNSt6__ndk119__shared_weak_countD2Ev'):
            self._ret(0)
            return
        if name in ('__cxa_pure_virtual', '_ZNKSt6__ndk119__shared_weak_count13__get_deleterERKSt9type_info'):
            self._ret(0)
            return
        if name == '__cxa_finalize':
            self._ret(0)
            return
        self.log.append(f'UNHANDLED IMPORT {name}')
        self._ret(0)

    # ---- minimal libc++ std::string (layout: byte0 flags, byte1 size, chars | long: cap,size,ptr) ----
    def _string_data(self, p):
        b = self.rds(p, 24)
        if b[0] & 1:
            ptr = struct.unpack_from('<Q', b, 16)[0]
            size = struct.unpack_from('<Q', b, 8)[0]
            return bytes(self.rds(ptr, size))
        size = b[1]
        return bytes(b[2:2 + size])

    def _destroy_string(self, p):
        pass

    def _mk_string(self, data):
        obj = self.alloc(32)
        buf = self.alloc(max(len(data) + 1, 1))
        self.uc.mem_write(buf, data + b'\0')
        hdr = struct.pack('<B', 1) + struct.pack('<B', 0) + struct.pack('<I', 0) + struct.pack('<Q', len(data)) + struct.pack('<Q', buf)
        self.uc.mem_write(obj, hdr)
        return obj

    def _string_op(self, name, args):
        self_, other = args[0], args[1]
        if 'C2ERKS5_' in name:      # copy ctor: _ZNSt6__ndk112basic_string...C2ERKS5_(this, const&)
            self.uc.mem_write(self_, self.rds(other, 24))
            self._ret(self_)
            return
        if 'aSERKS5_' in name:      # operator=
            self.uc.mem_write(self_, self.rds(other, 24))
            self._ret(self_)
            return
        if '5eraseEmm' in name:     # erase(pos, len)
            s = self._string_data(self_)
            pos, ln = args[1], args[2]
            new = s[:pos] + s[min(len(s), pos + ln):]
            t = self._mk_string(new)
            self.uc.mem_write(self_, self.rds(t, 24))
            self._ret(self_)
            return
        if '6appendEPKcm' in name:
            s = self._string_data(self_)
            add = bytes(self.rds(args[1], args[2]))
            t = self._mk_string(s + add)
            self.uc.mem_write(self_, self.rds(t, 24))
            self._ret(self_)
            return
        if '6assignEPKcm' in name:
            t = self._mk_string(bytes(self.rds(args[1], args[2])))
            self.uc.mem_write(self_, self.rds(t, 24))
            self._ret(self_)
            return
        if '9push_backEc' in name:
            s = self._string_data(self_)
            t = self._mk_string(s + bytes([args[1] & 0xff]))
            self.uc.mem_write(self_, self.rds(t, 24))
            self._ret(self_)
            return
        if '7reserveEm' in name:
            self._ret(self_)
            return
        self.log.append(f'UNHANDLED string op {name}')
        self._ret(self_)

    # ---------------- running ----------------
    def call(self, addr, args=(), timeout=0, count=2_000_000):
        uc = self.uc
        sp = uc.reg_read(UC_ARM64_REG_SP) - 0x100
        uc.reg_write(UC_ARM64_REG_SP, sp)
        ret_addr = self.ret_addr
        uc.reg_write(UC_ARM64_REG_LR, ret_addr)
        for i, a in enumerate(args):
            uc.reg_write(UC_ARM64_REG_X0 + i, a)
        self.halted = None
        try:
            uc.emu_start(addr, ret_addr, timeout=timeout, count=count)
        except UcError as ex:
            self.log.append(f'UC ERROR: {ex}')
            return None
        return uc.reg_read(UC_ARM64_REG_X0)

    def import_stub_map(self):
        return dict(self.imports)


def dump_memory(emu, out_prefix='/home/user/libng/analysis/out/mem'):
    import re
    uc, e = emu.uc, emu.e
    d = e.data
    # rebuild the file image per segment to diff
    e_phoff, = struct.unpack_from('<Q', d, 0x20)
    e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x36)
    changed = []
    diff_blob = bytearray()
    base = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from('<IIQQQQQQ', d, off)
        if p_type != 1:
            continue
        try:
            cur = bytes(uc.mem_read(p_vaddr, p_memsz))
        except UcError:
            continue
        orig = d[p_offset:p_offset + p_filesz] + b'\0' * (p_memsz - p_filesz)
        for k in range(0, min(len(cur), len(orig)), 4096):
            a, b = cur[k:k+4096], orig[k:k+4096]
            if a != b:
                # find exact changed spans within this page
                start = None
                pad = max(len(a), len(b))
                aa = a + b'\0' * (pad - len(a)); bb = b + b'\0' * (pad - len(b))
                for j in range(pad):
                    if aa[j] != bb[j]:
                        if start is None: start = j
                    else:
                        if start is not None:
                            changed.append((p_vaddr + k + start, p_vaddr + k + j))
                            start = None
                if start is not None:
                    changed.append((p_vaddr + k + start, p_vaddr + k + len(aa)))
        diff_blob += cur
    # merge adjacent spans
    merged = []
    for a, b in sorted(changed):
        if merged and a <= merged[-1][1] + 32:
            merged[-1][1] = max(merged[-1][1], b)
        else:
            merged.append([a, b])
    print(f'changed spans: {len(merged)}')
    with open(out_prefix + '_diff.bin', 'wb') as f:
        for a, b in merged:
            f.write(struct.pack('<QQ', a, b - a))
            f.write(bytes(uc.mem_read(a, b - a)))
    strings = []
    for a, b in merged:
        blk = bytes(uc.mem_read(a, b - a))
        for m in re.finditer(rb'[\x20-\x7e]{4,}', blk):
            strings.append((a + m.start(), m.group().decode('latin1')))
    with open(out_prefix + '_strings.txt', 'w') as f:
        for addr, st in strings:
            f.write(f'0x{addr:x}\t{st}\n')
    print(f'extracted {len(strings)} printable strings from changed memory -> {out_prefix}_strings.txt')
    return merged, strings


def main():
    emu = Emu()
    print('mapped OK, imports:', len(emu.imports))
    ia = emu.e.sections['.init_array']
    rel = emu.e.sections['.rela.dyn']
    d = emu.e.data
    init_funcs = []
    for i in range(rel['size'] // 24):
        off, info, add = struct.unpack_from('<QQq', d, rel['offset'] + i * 24)
        if (info & 0xffffffff) == 1027 and ia['addr'] <= off < ia['addr'] + ia['size']:
            init_funcs.append(((off - ia['addr']) // 8, add))
    init_funcs.sort()
    print('init_array funcs:', len(init_funcs))
    for idx, fn in init_funcs:
        print(f'--- running init[{idx}] @0x{fn:x} ---')
        r = emu.call(fn)
        print(f'    ret={r} halted={emu.halted} imports_called={len(emu.calls)}')
        if emu.log:
            for line in emu.log[-6:]:
                print('    ', line)
            emu.log = []
        if emu.halted:
            break
    dump_memory(emu)


if __name__ == '__main__':
    main()
