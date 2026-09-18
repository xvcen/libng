import struct

class ELF:
    def __init__(self, path):
        self.path = path
        self.data = open(path,'rb').read()
        d = self.data
        assert d[:4] == b'\x7fELF'
        self.is64 = d[4] == 2
        e_shoff, = struct.unpack_from('<Q', d, 0x28)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', d, 0x3a)
        self.sh = []
        for i in range(e_shnum):
            off = e_shoff + i*e_shentsize
            name, typ, flags, addr, offset, size, link, info, align, entsize = struct.unpack_from('<IIQQQQIIQQ', d, off)
            self.sh.append(dict(name_off=name, type=typ, flags=flags, addr=addr, offset=offset, size=size, link=link, info=info, align=align, entsize=entsize))
        strtab = self.sh[e_shstrndx]
        self.shstr = d[strtab['offset']:strtab['offset']+strtab['size']]
        for s in self.sh:
            s['name'] = self.cstr(s['name_off'], self.shstr)
        self.sections = {s['name']: s for s in self.sh}
        # dynsym
        self.syms = []
        ds = self.sections.get('.dynsym')
        if ds:
            strsec = self.sh[ds['link']]
            dstr = d[strsec['offset']:strsec['offset']+strsec['size']]
            for i in range(ds['size']//24):
                off = ds['offset'] + i*24
                nm, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', d, off)
                self.syms.append(dict(name=self.cstr(nm, dstr), info=info, shndx=shndx, value=value, size=size))
    @staticmethod
    def cstr(off, buf):
        end = buf.find(b'\0', off)
        return buf[off:end].decode('utf-8','replace') if end >= 0 else ''
    def va2off(self, va):
        for s in self.sh:
            if s['type'] != 8 and s['addr'] <= va < s['addr'] + s['size']:
                return s['offset'] + (va - s['addr'])
        return None
    def off2va(self, off):
        for s in self.sh:
            if s['type'] in (1,8): continue
            if s['offset'] <= off < s['offset'] + s['size']:
                return s['addr'] + (off - s['offset'])
        return None
    def read_va(self, va, n):
        off = self.va2off(va)
        return self.data[off:off+n] if off is not None else None
    def read_cstr_va(self, va, maxlen=400):
        off = self.va2off(va)
        if off is None: return None
        end = self.data.find(b'\0', off, off+maxlen)
        return self.data[off:end] if end >= 0 else None
    def section_of(self, va):
        for s in self.sh:
            if s['addr'] <= va < s['addr'] + s['size']:
                return s
        return None
