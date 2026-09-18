import sys, struct
sys.path.insert(0, '/home/user/libng/analysis')
from elf import ELF
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_OP_REG, ARM64_OP_IMM, ARM64_OP_MEM

class Dis:
    def __init__(self, path='/home/user/libng/libng.so'):
        self.e = ELF(path)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.md.detail = True
    def dis(self, va, n):
        code = self.e.read_va(va, n)
        out = []
        adrp = {}
        for ins in self.md.disasm(code, va):
            txt = f"{ins.address:08x}: {ins.mnemonic:<8} {ins.op_str}"
            note = ''
            m = ins.mnemonic
            ops = ins.operands
            # track adrp -> compute target; adrp base is page of pc
            if m == 'adrp' and len(ops) == 2 and ops[1].type == ARM64_OP_IMM:
                adrp[ops[0].reg] = ops[1].imm
            elif m in ('add','ldr','str','ldrb','ldrh','ldrsw','strb','ldur','stur','adds') and ops:
                base = None
                off = 0
                if len(ops) >= 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                    if ops[1].reg in adrp and m == 'add':
                        target = adrp[ops[1].reg] + ops[2].imm
                        note = f'  ; =0x{target:x}'
                        s = self.e.read_cstr_va(target, 64)
                        if s is not None:
                            printable = ''.join(chr(c) if 32<=c<127 else f'\\x{c:02x}' for c in s)
                            note += f' "{printable}"'
                        adrp.pop(ops[1].reg, None)
                if len(ops) >= 2 and ops[1].type == ARM64_OP_MEM and ops[1].mem.base in adrp:
                    target = adrp[ops[1].mem.base] + ops[1].mem.disp
                    note = f'  ; =0x{target:x}'
                    raw = self.e.read_va(target, 8)
                    if raw: note += ' raw=' + raw.hex()
                    if m in ('ldr','ldrb','ldrh','ldrsw'):
                        adrp.pop(ops[1].mem.base, None)
            elif m in ('b','bl') and ops and ops[0].type == ARM64_OP_IMM:
                target = ops[0].imm
                note = f'  ; ->0x{target:x}'
                nm = self.name_at(target)
                if nm: note += f' {nm}'
            elif m == 'bl' and ops and ops[0].type == ARM64_OP_REG:
                pass
            elif m in ('cbz','cbnz') and len(ops)==2 and ops[1].type == ARM64_OP_IMM:
                note = f'  ; ->0x{ops[1].imm:x}'
            print(txt + note)
    def name_at(self, va):
        for s in self.e.syms:
            if s['value'] == va and s['name']:
                return s['name']
        # plt
        plt = self.e.sections['.plt']
        if plt['addr'] <= va < plt['addr']+plt['size']:
            return f'plt[{va:x}]'
        return None

if __name__ == '__main__':
    d = Dis()
    va = int(sys.argv[1], 16)
    n = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x100
    d.dis(va, n)
