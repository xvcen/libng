#!/usr/bin/env python3
"""
procmem_dump.py — снятие расшифрованных данных libng.so БЕЗ инъекции (только root).

Работает через /proc/<pid>/maps + /proc/<pid>/mem, поэтому не палится
анти-Frida/анти-хук проверками библиотеки.

Запуск (в Termux, под root — через tsu или su -c):
    tsu
    python3 procmem_dump.py --pkg com.example.game --rounds 30 --interval 5 --out /sdcard/ngdump

Каждый раунд: снапшот региона модуля + heap -> .bin + .json (индекс регионов).
Строки извлекаются сразу (новые относительно оригинального .so).
"""
import argparse, json, os, re, struct, subprocess, sys, time


def sh(cmd, root=False):
    if root:
        cmd = ['su', '-c', cmd]
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)


def find_pid(pkg):
    for pat in ('pidof %s' % pkg, 'pgrep -f %s' % pkg):
        out = sh(pat).stdout.strip().split()
        if out:
            try:
                return int(out[0])
            except ValueError:
                pass
    out = sh("ps -A | grep %s" % pkg).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0].isdigit():
            return int(parts[0])
    return None


def read_maps(pid):
    with open('/proc/%d/maps' % pid) as f:
        maps = []
        for line in f:
            m = re.match(r'([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)', line)
            if not m:
                continue
            start, end, perms, path = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4).strip()
            maps.append({'start': start, 'end': end, 'perms': perms, 'path': path})
        return maps


def wanted(r, mod_base, mod_end):
    p = r['path']
    if 'libng.so' in p:
        return True
    if '[heap]' in p or 'libc_malloc' in p or 'scudo' in p:
        return True
    # анонимные rw-регионы в окне ±64 МБ от модуля (таблицы/арены)
    if p == '' and 'w' in r['perms'] and mod_base - 0x4000000 <= r['start'] <= mod_end + 0x4000000:
        return True
    return False


def snapshot(pid, out_path, max_region=64 * 1024 * 1024):
    maps = read_maps(pid)
    mods = [r for r in maps if 'libng.so' in r['path']]
    if not mods:
        return None
    mod_base, mod_end = mods[0]['start'], mods[-1]['end']
    regions, total = [], 0
    with open(out_path, 'wb') as fb, open('/proc/%d/mem' % pid, 'rb', buffering=0) as fm:
        for r in maps:
            if not wanted(r, mod_base, mod_end):
                continue
            size = r['end'] - r['start']
            if size <= 0 or size > max_region:
                continue
            try:
                fm.seek(r['start'])
                data = fm.read(size)
            except (OSError, ValueError):
                continue
            if len(data) != size:
                continue
            regions.append({'start': r['start'], 'size': size, 'perms': r['perms'],
                            'path': r['path'], 'file_off': total})
            fb.write(data)
            total += size
    index = {'pid': pid, 'module': {'base': mod_base, 'end': mod_end},
             'regions': regions, 'total': total, 'time': time.time()}
    with open(out_path.replace('.bin', '.json'), 'w') as fj:
        json.dump(index, fj, indent=1)
    return index


def baseline_strings(so_path):
    if not so_path or not os.path.exists(so_path):
        return set()
    with open(so_path, 'rb') as f:
        blob = f.read()
    return set(m.group() for m in re.finditer(rb'[\x20-\x7e]{6,}', blob))


STR_RE = re.compile(rb'[\x20-\x7e]{6,}')
U16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){6,}')


def extract_strings(bin_path, json_path, baseline):
    idx = json.load(open(json_path))
    blob = open(bin_path, 'rb').read()
    found = {}
    for r in idx['regions']:
        seg = blob[r['file_off']:r['file_off'] + r['size']]
        for m in STR_RE.finditer(seg):
            if m.group() in baseline:
                continue
            found[r['start'] + m.start()] = m.group().decode('latin1')
        for m in U16_RE.finditer(seg):
            if m.group() in baseline:
                continue
            found[r['start'] + m.start()] = m.group().decode('utf-16-le', 'replace')
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pkg', help='имя пакета приложения, использующего libng.so')
    ap.add_argument('--pid', type=int, help='PID (если уже известен)')
    ap.add_argument('--out', default='ngdump')
    ap.add_argument('--rounds', type=int, default=20)
    ap.add_argument('--interval', type=float, default=5.0)
    ap.add_argument('--orig', help='путь к оригинальному libng.so (для фильтра «уже было в файле»)')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    baseline = baseline_strings(args.orig)
    all_strings = {}
    for i in range(args.rounds):
        pid = args.pid or find_pid(args.pkg)
        if not pid:
            print('[!] процесс не найден (запусти приложение)'); time.sleep(args.interval); continue
        tag = 'r%02d' % i
        bin_path = os.path.join(args.out, 'ng_%s.bin' % tag)
        idx = snapshot(pid, bin_path)
        if not idx:
            print('[!] libng.so не замаплен в pid %d' % pid); time.sleep(args.interval); continue
        new = extract_strings(bin_path, bin_path.replace('.bin', '.json'), baseline)
        fresh = {a: s for a, s in new.items() if a not in all_strings}
        all_strings.update(new)
        print('[+] %s pid=%d регионов=%d, всего=%d КБ, новых строк=%d (всего %d)' %
              (tag, pid, len(idx['regions']), idx['total'] // 1024, len(fresh), len(all_strings)))
        # накопленная база строк
        with open(os.path.join(args.out, 'strings_runtime.csv'), 'w') as f:
            f.write('addr,string\n')
            for a in sorted(all_strings):
                f.write('0x%x,"%s"\n' % (a, all_strings[a].replace('"', '""')))
        time.sleep(args.interval)
    print('[+] готово: %s/strings_runtime.csv + снапшоты ng_*.bin/.json' % args.out)


if __name__ == '__main__':
    main()
