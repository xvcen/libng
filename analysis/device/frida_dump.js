/*
 * frida_dump.js — снять с живого процесса расшифрованные данные libng.so.
 *
 * Использование (host-сторона — frida_host.py):
 *   frida -U -f <package> -l frida_dump.js      (или через frida_host.py)
 *
 * Возможности:
 *   rpc.exports.dumpall(tag)        — дамп всех регионов модуля + heap
 *   rpc.exports.call(name, args)    — вызвать экспорт libng.so с аргументами
 *   rpc.exports.exprobe(tag)        — обход по нескольким вызовам + дампы
 *   rpc.exports.scan(tag)           — только поиск "новых" строк (дифф по памяти)
 *   rpc.exports.modinfo()           — адреса/размеры регионов
 */
'use strict';

const MODNAME = 'libng.so';
let mod = null;

function findMod() {
    if (mod) return mod;
    mod = Process.findModuleByName(MODNAME);
    return mod;
}

function b64(bytes) {
    const CH = 0x8000;
    let out = '';
    for (let i = 0; i < bytes.length; i += CH) {
        out += btoa(String.fromCharCode.apply(null, bytes.slice(i, i + CH)));
    }
    return out;
}

function readBytes(addr, size) {
    const p = Memory.readByteArray(ptr(addr), size);
    return new Uint8Array(p);
}

/* все регионы модуля (r--, r-x, rw-) + heap-подобные анонимные rw-регионы рядом */
function targetRegions() {
    const m = findMod();
    if (!m) throw new Error(MODNAME + ' not loaded');
    const modEnd = m.base.add(m.size);
    const out = [];
    m.enumerateRanges('---').forEach(r => out.push({ base: r.base, size: r.size, protection: r.protection, path: m.path, kind: 'module' }));
    Process.enumerateRanges('rw-').forEach(r => {
        if (r.base.compare(m.base) >= 0 && r.base.compare(modEnd) < 0) return; // уже есть
        const name = r.file ? r.file.path : '';
        if (name === '' || /\[heap\]|libc_malloc|dalvik|scudo/.test(name)) {
            if (r.size <= 64 * 1024 * 1024) {
                out.push({ base: r.base, size: r.size, protection: r.protection, path: name, kind: 'heap' });
            }
        }
    });
    return out;
}

function dumpRegions(tag, regions) {
    let total = 0;
    for (const r of regions) {
        const CHUNK = 1 << 20;
        for (let off = 0; off < r.size; off += CHUNK) {
            const n = Math.min(CHUNK, r.size - off);
            let data;
            try { data = readBytes(r.base.add(off), n); }
            catch (e) { continue; }
            total += n;
            send({
                t: 'chunk', tag: tag,
                base: r.base.add(off).toString(), size: n,
                region_base: r.base.toString(), region_size: r.size,
                path: r.path, kind: r.kind,
                data: b64(data)
            });
        }
    }
    send({ t: 'dump_done', tag: tag, total: total });
    return total;
}

const EXPORTS = ['register_callback', 'get_heartbeat_data', 'set_player_token', 'is_emulator', 'ng_ioctl', 'JNI_OnLoad'];

rpc.exports = {
    modinfo() {
        const m = findMod();
        if (!m) return null;
        return { base: m.base.toString(), size: m.size, path: m.path,
                 exports: m.enumerateExports().filter(e => EXPORTS.indexOf(e.name) >= 0)
                            .map(e => ({ name: e.name, address: e.address.toString() })) };
    },
    dumpall(tag) {
        const regions = targetRegions();
        return dumpRegions(tag || 'frida', regions);
    },
    /* адреса экспортов */
    addrs() {
        const m = findMod();
        const r = {};
        m.enumerateExports().forEach(e => { if (EXPORTS.indexOf(e.name) >= 0) r[e.name] = e.address; });
        return r;
    },
    /* аккуратный вызов экспорта: call('is_emulator', []) и т.п. */
    call(name, args) {
        const a = this.addrs();
        if (!a[name]) throw new Error('no export ' + name);
        const types = { register_callback: ['pointer', 'pointer'],
                        get_heartbeat_data: ['pointer'],
                        set_player_token: ['pointer', 'int'],
                        is_emulator: [],
                        ng_ioctl: ['long', 'pointer', 'long', 'long'],
                        JNI_OnLoad: ['pointer', 'pointer'] }[name];
        const f = new NativeFunction(a[name], 'long', types);
        const buf = Memory.alloc(0x4000);
        const mapped = (args || []).map(x => (x === 'buf' ? buf : x));
        return f.apply(null, mapped);
    },
    /* прогрев: вызвать всё, что можно, затем дамп */
    exprobe(tag) {
        const res = {};
        const safe = (n, fn) => { try { res[n] = fn(); } catch (e) { res[n] = 'ERR: ' + e; } };
        safe('is_emulator', () => this.call('is_emulator', []));
        safe('set_player_token', () => this.call('set_player_token', ['buf', 64]));
        safe('register_callback', () => this.call('register_callback', ['buf', 'buf']));
        safe('get_heartbeat_data', () => this.call('get_heartbeat_data', ['buf']));
        safe('ng_ioctl_0', () => this.call('ng_ioctl', [0, 'buf', 64, 0]));
        send({ t: 'probe_result', res: JSON.stringify(res) });
        return dumpRegions(tag || 'probe', targetRegions());
    },
    /* только поиск строк: быстро, без записи мегабайт */
    scan(tag) {
        const m = findMod();
        const regions = targetRegions();
        const re = /[\x20-\x7e]{6,}/g;
        let hits = 0;
        for (const r of regions) {
            if (r.size > 32 * 1024 * 1024) continue;
            let data;
            try { data = readBytes(r.base, r.size); } catch (e) { continue; }
            let s = '';
            for (let i = 0; i < data.length; i++) s += String.fromCharCode(data[i]);
            let mm;
            while ((mm = re.exec(s)) !== null) {
                hits++;
                send({ t: 'string', tag: tag, addr: r.base.add(mm.index).toString(), s: mm[0] });
                if (hits > 200000) return hits;
            }
        }
        return hits;
    }
};

/* авто-дамп сразу после загрузки модуля (удобно при -f spawn) */
(function autoWait() {
    let tries = 0;
    const t = setInterval(() => {
        if (findMod()) {
            clearInterval(t);
            send({ t: 'module_loaded', info: JSON.stringify(rpc.exports.modinfo()) });
        } else if (++tries > 600) {
            clearInterval(t);
            send({ t: 'error', msg: MODNAME + ' not found after 60s' });
        }
    }, 100);
})();
