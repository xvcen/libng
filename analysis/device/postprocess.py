#!/usr/bin/env python3
"""
postprocess.py — собрать все дампы (frida_*.bin/.json и/или ng_*.bin/.json)
в один «словарь расшифрованного»:
  * строки (ASCII + UTF-16) с адресами, отфильтрованные от того, что уже было в файле;
  * карта регионов и таблиц;
  * CSV + бинарь-образ для дальнейшего импорта в IDA/Ghidra.

Запуск:
    python3 postprocess.py ngdump [--orig /path/libng.so]
"""
import argparse, glob, json, os, re, struct, sys

STR_RE = re.compile(rb'[\x20-\x7e]{6,}')
U16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')

SEC_NAMES = [('.text', 0x2019d0, 0x4e1f90), ('.rodata', 0xa5450, 0x1fd00), ('.ark', 0xc5150, 0xb4ce0),
             ('.data', 0x6f72e0, 0xae8d0), ('.bss', 0x7a5bb0, 0x408bd0)]


def sec_of(addr):
    for n, a, s in SEC_NAMES:
        if a <= addr < a + s:
            return n
    return '?'


def baseline(path):
    if not path or not os.path.exists(path):
        return set()
    blob = open(path, 'rb').read()
    return set(m.group() for m in STR_RE.finditer(blob))


def iter_dumps(dumpdir):
    for jspath in sorted(glob.glob(os.path.join(dumpdir, '*.json'))):
        if jspath.endswith('strings_runtime.json'):
            continue
        binpath = jspath[:-5] + '.bin'
        if not os.path.exists(binpath):
            continue
        try:
            idx = json.load(open(jspath))
        except Exception:
            continue
        blob = open(binpath, 'rb').read()
        if 'regions' in idx:                      # procmem_dump-стиль
            for r in idx['regions']:
                yield jspath, r.get('start'), blob[r['file_off']:r['file_off'] + r['size']], r.get('path', '')
        elif 'chunks' in idx:                     # frida_host-стиль
            for c in idx['chunks']:
                yield jspath, int(c['base'], 16), blob[c['file_off']:c['file_off'] + c['size']], c.get('path', '')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dumpdir')
    ap.add_argument('--orig', help='оригинальный libng.so (чтобы отфильтровать уже известные строки)')
    ap.add_argument('--out', default=None)
    args = ap.parse_args()
    outdir = args.out or args.dumpdir
    base = baseline(args.orig)

    strings = {}
    totals = {}
    for js, start, seg, path in iter_dumps(args.dumpdir):
        if start is None:
            continue
        totals[js] = totals.get(js, 0) + len(seg)
        for m in STR_RE.finditer(seg):
            s = m.group()
            if s in base:
                continue
            strings.setdefault(start + m.start(), s.decode('latin1'))
        for m in U16_RE.finditer(seg):
            s = m.group()
            if s in base:
                continue
            strings.setdefault(start + m.start(), s.decode('utf-16-le', 'replace'))

    csv_path = os.path.join(outdir, 'decrypted_strings.csv')
    with open(csv_path, 'w') as f:
        f.write('addr,section,string\n')
        for a in sorted(strings):
            f.write('0x%x,%s,"%s"\n' % (a, sec_of(a), strings[a].replace('"', '""')))

    print('дампов обработано: %d, байт: %d' % (len(totals), sum(totals.values())))
    for js, n in sorted(totals.items()):
        print('   %-40s %8.1f КБ' % (os.path.basename(js), n / 1024))
    print('уникальных расшифрованных строк: %d -> %s' % (len(strings), csv_path))
    print('топ-40 по длине:')
    for a in sorted(strings, key=lambda x: -len(strings[x]))[:40]:
        print('   0x%08x %-6s %s' % (a, sec_of(a), strings[a][:120]))


if __name__ == '__main__':
    main()
