#!/usr/bin/env python3
"""
frida_host.py — host-сторона для frida_dump.js (запускается на ПК или прямо в Termux).

Примеры:
    # прицепиться к уже запущенному приложению и сразу снять дамп
    python3 frida_host.py -U -n com.example.game --dump after_load

    # запустить приложение под Frida, подождать загрузку libng.so, прогреть API и дампить
    python3 frida_host.py -U -f com.example.game --probe

    # дополнительно брутфорс ng_ioctl (ОСТОРОЖНО: может уронить приложение — сначала сохрани дампы)
    python3 frida_host.py -U -n com.example.game --ioctl 0 0x200

Требуется: pip install frida frida-tools ; на устройстве — frida-server, запущенный от root.
"""
import argparse, base64, json, os, sys, time

try:
    import frida
except ImportError:
    sys.exit('pip install frida (в Termux: pip install frida)')

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida_dump.js')


class Receiver:
    def __init__(self, outdir):
        self.outdir = outdir
        os.makedirs(outdir, exist_ok=True)
        self.files = {}
        self.index = {}
        self.strings = []
        self.probe = None
        self.modinfo = None

    def on_message(self, message, data):
        if message.get('type') != 'send':
            print('[frida]', message)
            return
        p = message['payload']
        t = p.get('t')
        if t == 'chunk':
            path = os.path.join(self.outdir, 'frida_%s.bin' % p['tag'])
            f = self.files.get(path)
            if f is None:
                f = open(path, 'wb')
                self.files[path] = f
                self.index[path] = {'regions': [], 'chunks': []}
            raw = base64.b64decode(p['data'])
            off = f.tell()
            f.write(raw)
            self.index[path]['chunks'].append({'base': p['base'], 'size': p['size'],
                                               'region_base': p['region_base'],
                                               'region_size': p['region_size'],
                                               'path': p['path'], 'kind': p['kind'], 'file_off': off})
        elif t == 'dump_done':
            path = os.path.join(self.outdir, 'frida_%s.bin' % p['tag'])
            if path in self.files:
                self.files[path].close()
                with open(path.replace('.bin', '.json'), 'w') as fj:
                    json.dump(self.index[path], fj, indent=1)
            print('[+] дамп %s: %d байт -> %s' % (p['tag'], p['total'], path))
        elif t == 'string':
            self.strings.append((p['addr'], p['s']))
        elif t == 'probe_result':
            self.probe = p['res']
            print('[+] probe:', p['res'])
        elif t == 'module_loaded':
            self.modinfo = p['info']
            print('[+] module:', p['info'])
        elif t == 'error':
            print('[!] ' + p['msg'])


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('-f', '--spawn', help='spawn приложения по package name')
    g.add_argument('-n', '--attach-name', help='attach к запущенному приложению')
    g.add_argument('-p', '--attach-pid', type=int)
    ap.add_argument('-U', '--usb', action='store_true', default=True, help='устройство по USB (по умолчанию)')
    ap.add_argument('-H', '--host', help='frida-server host:port (если не USB)')
    ap.add_argument('--dump', metavar='TAG', help='сразу снять дамп с тегом TAG')
    ap.add_argument('--probe', action='store_true', help='вызвать экспорты libng.so и снять дамп')
    ap.add_argument('--ioctl', nargs=2, type=lambda x: int(x, 0), metavar=('LO', 'HI'),
                    help='брутфорс ng_ioctl(cmd) в диапазоне; дамп после каждой 0x1000')
    ap.add_argument('--scan', metavar='TAG', help='только сканировать строки')
    ap.add_argument('--out', default='ngdump')
    args = ap.parse_args()

    dev = frida.get_device_manager().add_remote_device(args.host) if args.host else frida.get_usb_device(timeout=10)
    if args.spawn:
        pid = dev.spawn([args.spawn])
        session = dev.attach(pid)
        dev.resume(pid)
        print('[+] spawned', args.spawn, 'pid', pid)
    elif args.attach_name:
        session = dev.attach(args.attach_name)
    else:
        session = dev.attach(args.attach_pid)

    recv = Receiver(args.out)
    script = session.create_script(open(SCRIPT).read())
    script.on('message', recv.on_message)
    script.load()
    print('[+] скрипт загружен; ждём libng.so ...')
    for _ in range(120):
        info = script.exports_sync.modinfo()
        if info:
            print('[+] libng.so:', info)
            break
        time.sleep(1)
    else:
        print('[!] libng.so не появился за 120 c')

    if args.dump:
        script.exports_sync.dumpall(args.dump)
    if args.probe:
        script.exports_sync.exprobe('probe')
    if args.ioctl:
        lo, hi = args.ioctl
        print('[!] брутфорс ioctl 0x%x..0x%x — приложение может упасть!' % (lo, hi))
        for cmd in range(lo, hi, 0x100):
            for c in range(cmd, min(cmd + 0x100, hi)):
                try:
                    script.exports_sync.call('ng_ioctl', [c, 'buf', 64, 0])
                except Exception as e:
                    print('[!] ioctl 0x%x -> %s' % (c, e))
            script.exports_sync.dumpall('ioctl_%x' % cmd)
    if args.scan:
        n = script.exports_sync.scan(args.scan)
        print('[+] найдено строк:', n)
        with open(os.path.join(args.out, 'strings_frida.csv'), 'w') as f:
            f.write('addr,string\n')
            for a, s in recv.strings:
                f.write('%s,"%s"\n' % (a, s.replace('"', '""')))
        print('[+] сохранено в', os.path.join(args.out, 'strings_frida.csv'))

    print('[+] дампы в', os.path.abspath(args.out))
    print('[i] дальше: python3 postprocess.py %s' % args.out)


if __name__ == '__main__':
    main()
