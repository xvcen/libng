"""Run libng.so JNI_OnLoad (and other exports) under Unicorn with a fake JNI env.

Intercepts:
  * JavaVM (JNIInvokeInterface) and JNIEnv (JNINativeInterface) calls  -> logs names/args
  * __system_property_get                                              -> logs property names
  * RegisterNatives                                                    -> dumps the native method table
"""
import sys, os, struct, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emu import Emu
from unicorn import *
from unicorn.arm64_const import *

JNIENV_BASE = 0x51000000
JNIVM_BASE = 0x51001000
FAKE_VM = 0x52000000
FAKE_ENV = 0x52000100
STRPOOL = 0x53000000
STRPOOL_SIZE = 0x100000

JNIENV_NAMES = {}
_names = """reserved0 reserved1 reserved2 reserved3 GetVersion DefineClass FindClass FromReflectedMethod
FromReflectedField ToReflectedMethod GetSuperclass IsAssignableFrom ToReflectedField Throw ThrowNew
ExceptionOccurred ExceptionDescribe ExceptionClear FatalError PushLocalFrame PopLocalFrame NewGlobalRef
DeleteGlobalRef DeleteLocalRef IsSameObject NewLocalRef EnsureLocalCapacity AllocObject NewObject NewObjectV
NewObjectA GetObjectClass IsInstanceOf GetMethodID CallObjectMethod CallObjectMethodV CallObjectMethodA
CallBooleanMethod CallBooleanMethodV CallBooleanMethodA CallByteMethod CallByteMethodV CallByteMethodA
CallCharMethod CallCharMethodV CallCharMethodA CallShortMethod CallShortMethodV CallShortMethodA
CallIntMethod CallIntMethodV CallIntMethodA CallLongMethod CallLongMethodV CallLongMethodA CallFloatMethod
CallFloatMethodV CallFloatMethodA CallDoubleMethod CallDoubleMethodV CallDoubleMethodA CallVoidMethod
CallVoidMethodV CallVoidMethodA CallNonvirtualObjectMethod CallNonvirtualObjectMethodV CallNonvirtualObjectMethodA
CallNonvirtualBooleanMethod CallNonvirtualBooleanMethodV CallNonvirtualBooleanMethodA CallNonvirtualByteMethod
CallNonvirtualByteMethodV CallNonvirtualByteMethodA CallNonvirtualCharMethod CallNonvirtualCharMethodV
CallNonvirtualCharMethodA CallNonvirtualShortMethod CallNonvirtualShortMethodV CallNonvirtualShortMethodA
CallNonvirtualIntMethod CallNonvirtualIntMethodV CallNonvirtualIntMethodA CallNonvirtualLongMethod
CallNonvirtualLongMethodV CallNonvirtualLongMethodA CallNonvirtualFloatMethod CallNonvirtualFloatMethodV
CallNonvirtualFloatMethodA CallNonvirtualDoubleMethod CallNonvirtualDoubleMethodV CallNonvirtualDoubleMethodA
CallNonvirtualVoidMethod CallNonvirtualVoidMethodV CallNonvirtualVoidMethodA GetFieldID GetObjectField
GetBooleanField GetByteField GetCharField GetShortField GetIntField GetLongField GetFloatField GetDoubleField
SetObjectField SetBooleanField SetByteField SetCharField SetShortField SetIntField SetLongField SetFloatField
SetDoubleField GetStaticMethodID CallStaticObjectMethod CallStaticObjectMethodV CallStaticObjectMethodA
CallStaticBooleanMethod CallStaticBooleanMethodV CallStaticBooleanMethodA CallStaticByteMethod
CallStaticByteMethodV CallStaticByteMethodA CallStaticCharMethod CallStaticCharMethodV CallStaticCharMethodA
CallStaticShortMethod CallStaticShortMethodV CallStaticShortMethodA CallStaticIntMethod CallStaticIntMethodV
CallStaticIntMethodA CallStaticLongMethod CallStaticLongMethodV CallStaticLongMethodA CallStaticFloatMethod
CallStaticFloatMethodV CallStaticFloatMethodA CallStaticDoubleMethod CallStaticDoubleMethodV
CallStaticDoubleMethodA CallStaticVoidMethod CallStaticVoidMethodV CallStaticVoidMethodA GetStaticFieldID
GetStaticObjectField GetStaticBooleanField GetStaticByteField GetStaticCharField GetStaticShortField
GetStaticIntField GetStaticLongField GetStaticFloatField GetStaticDoubleField SetStaticObjectField
SetStaticBooleanField SetStaticByteField SetStaticCharField SetStaticShortField SetStaticIntField
SetStaticLongField SetStaticFloatField SetStaticDoubleField NewString GetStringLength GetStringChars
ReleaseStringChars NewStringUTF GetStringUTFLength GetStringUTFChars ReleaseStringUTFChars GetArrayLength
NewObjectArray GetObjectArrayElement SetObjectArrayElement NewBooleanArray NewByteArray NewCharArray
NewShortArray NewIntArray NewLongArray NewFloatArray NewDoubleArray GetBooleanArrayElements
GetByteArrayElements GetCharArrayElements GetShortArrayElements GetIntArrayElements GetLongArrayElements
GetFloatArrayElements GetDoubleArrayElements ReleaseBooleanArrayElements ReleaseByteArrayElements
ReleaseCharArrayElements ReleaseShortArrayElements ReleaseIntArrayElements ReleaseLongArrayElements
ReleaseFloatArrayElements ReleaseDoubleArrayElements GetBooleanArrayRegion GetByteArrayRegion GetCharArrayRegion
GetShortArrayRegion GetIntArrayRegion GetLongArrayRegion GetFloatArrayRegion GetDoubleArrayRegion
SetBooleanArrayRegion SetByteArrayRegion SetCharArrayRegion SetShortArrayRegion SetIntArrayRegion
SetLongArrayRegion SetFloatArrayRegion SetDoubleArrayRegion RegisterNatives UnregisterNatives MonitorEnter
MonitorExit GetJavaVM GetStringRegion GetStringUTFRegion GetPrimitiveArrayCritical ReleasePrimitiveArrayCritical
GetStringCritical ReleaseStringCritical NewWeakGlobalRef DeleteWeakGlobalRef ExceptionCheck NewDirectByteBuffer
GetDirectBufferAddress GetDirectBufferCapacity GetObjectRefType GetModule""".split()
for i, n in enumerate(_names):
    JNIENV_NAMES[i] = n

VM_NAMES = {3: 'DestroyJavaVM', 4: 'AttachCurrentThread', 5: 'DetachCurrentThread', 6: 'GetEnv',
            7: 'AttachCurrentThreadAsDaemon'}


class JniEmu(Emu):
    def __init__(self, *a, **kw):
        self.jni_log = []
        self.props = []
        super().__init__(*a, **kw)
        uc = self.uc
        # stub pages: 1 instruction per entry (RET), we intercept before execution
        uc.mem_map(JNIENV_BASE, 0x1000)
        uc.mem_map(JNIVM_BASE, 0x1000)
        uc.mem_write(JNIENV_BASE, b'\xc0\x03\x5f\xd6' * (0x1000 // 4))
        uc.mem_write(JNIVM_BASE, b'\xc0\x03\x5f\xd6' * (0x1000 // 4))
        uc.mem_map(FAKE_VM & ~0xfff, 0x2000)
        uc.mem_map(STRPOOL, STRPOOL_SIZE)
        self.strpool = STRPOOL + 8
        self.jstr_map = {}
        # build vtables: JavaVM struct at FAKE_VM -> vtable ptr ; vtable = 8 reserved + 8 fns
        vm_vtable = STRPOOL  # placeholder, will build properly below
        vt = self.alloc(8 * 16)
        for i in range(16):
            self.uc.mem_write(vt + i * 8, struct.pack('<Q', JNIVM_BASE + i * 4))
        self.uc.mem_write(FAKE_VM, struct.pack('<Q', vt))
        self.vm = FAKE_VM
        env_vt = self.alloc(8 * 256)
        for i in range(256):
            self.uc.mem_write(env_vt + i * 8, struct.pack('<Q', JNIENV_BASE + i * 4))
        self.uc.mem_write(FAKE_ENV, struct.pack('<Q', env_vt))
        self.env = FAKE_ENV
        # extra hooks
        self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self._hook_mem, begin=STRPOOL, end=STRPOOL + STRPOOL_SIZE)

    def _hook_mem(self, uc, access, address, size, value, user):
        return True

    def _hook_code(self, uc, address, size, user):
        if JNIENV_BASE <= address < JNIENV_BASE + 0x1000:
            idx = (address - JNIENV_BASE) // 4
            self._jni_env_call(idx)
            return
        if JNIVM_BASE <= address < JNIVM_BASE + 0x1000:
            idx = (address - JNIVM_BASE) // 4
            self._jni_vm_call(idx)
            return
        super()._hook_code(uc, address, size, user)

    def _mk_utf(self, data):
        p = self.strpool
        self.strpool += (len(data) + 1 + 7) & ~7
        self.uc.mem_write(p, data + b'\0')
        return p

    def _jni_env_call(self, idx):
        uc = self.uc
        name = JNIENV_NAMES.get(idx, f'jni_{idx}')
        args = [self.rd(UC_ARM64_REG_X0 + i) for i in range(8)]
        env = args[0]
        log = {'fn': name, 'idx': idx, 'args': [hex(a) for a in args[1:6]]}
        # decode string args where the API takes const char*
        if name in ('FindClass', 'ThrowNew', 'DefineClass'):
            log['str'] = self.cstr(args[1])
        elif name in ('GetMethodID', 'GetStaticMethodID', 'GetFieldID', 'GetStaticFieldID'):
            log['class'] = hex(args[1])
            log['name'] = self.cstr(args[2])
            log['sig'] = self.cstr(args[3])
        elif name in ('NewStringUTF', 'GetStringUTFLength', 'GetStringUTFChars'):
            log['str'] = self.cstr(args[1])
        elif name == 'RegisterNatives':
            clazz, methods, n = args[1], args[2], args[3]
            log['count'] = n
            meths = []
            for i in range(min(n, 64)):
                nm, sig, fn = struct.unpack_from('<QQQ', bytes(self.rds(methods + i * 24, 24)), 0)
                meths.append({'name': self.cstr(nm), 'sig': self.cstr(sig) if sig else None,
                              'fn': hex(fn)})
            log['methods'] = meths
        elif name in ('CallStaticObjectMethod', 'GetStaticObjectField'):
            log['method'] = hex(args[2])
        elif name in ('NewObject', 'CallObjectMethod'):
            log['method'] = hex(args[2])
        log['args'] = [hex(a) for a in args[1:6]]
        self.jni_log.append(log)
        # --- semantics ---
        if name == 'GetVersion':
            self._ret(0x00010006)
            return
        if name == 'NewStringUTF':
            h = self._mk_utf(self.cstr(args[1]) or b'')
            self.jstr_map[h] = self.cstr(args[1]) or b''
            self._ret(h)
            return
        if name == 'GetStringUTFChars':
            data = self.jstr_map.get(args[1], b'')
            self._ret(self._mk_utf(data))
            return
        if name == 'GetStringUTFLength':
            self._ret(len(self.jstr_map.get(args[1], b'')))
            return
        if name in ('FindClass',):
            self._ret(0x11110000 + idx)
            return
        if name in ('GetObjectClass',):
            self._ret(0x22220000)
            return
        if name == 'GetJavaVM':
            self.uc.mem_write(args[1], struct.pack('<Q', self.vm))
            self._ret(0)
            return
        if name in ('ExceptionCheck', 'ExceptionOccurred', 'PushLocalFrame'):
            self._ret(0)
            return
        if name in ('NewGlobalRef', 'NewLocalRef'):
            self._ret(args[1] if args[1] else 0x33330000)
            return
        if name == 'AttachCurrentThread' or name == 'GetEnv':
            self._ret(0)
            return
        if name.startswith('Call') or name.startswith('Get') or name.startswith('Set'):
            self._ret(0)
            return
        self._ret(0)

    def _jni_vm_call(self, idx):
        name = VM_NAMES.get(idx, f'vm_{idx}')
        args = [self.rd(UC_ARM64_REG_X0 + i) for i in range(6)]
        self.jni_log.append({'fn': 'JavaVM::' + name, 'idx': idx, 'args': [hex(a) for a in args[1:5]]})
        if name in ('GetEnv', 'AttachCurrentThread', 'AttachCurrentThreadAsDaemon'):
            out = args[1]
            if out:
                self.uc.mem_write(out, struct.pack('<Q', self.env))
            self._ret(0)
            return
        self._ret(0)

    def _do_import(self, name):
        if name == '__system_property_get':
            prop = self.cstr(self.rd(UC_ARM64_REG_X0)) or b''
            out = self.rd(UC_ARM64_REG_X1)
            self.props.append(prop.decode('latin1'))
            if out:
                self.uc.mem_write(out, b'\0')
            self._ret(0)
            return
        if name == 'dl_iterate_phdr':
            self._ret(0)
            return
        super()._do_import(name)


def run(path='/home/user/libng/libng.so', func='JNI_OnLoad', outdir='/home/user/libng/analysis/out'):
    emu = JniEmu(path)
    sym = [s for s in emu.e.syms if s['name'] == func]
    if not sym:
        print('no such export', func)
        return
    addr = sym[0]['value']
    print(f'running {func} @0x{addr:x} with JavaVM=0x{emu.vm:x}, JNIEnv=0x{emu.env:x}')
    r = emu.call(addr, (emu.vm, 0), count=20_000_000)
    print('return value:', r, 'halted:', emu.halted)
    with open(os.path.join(outdir, f'{func}_jni.json'), 'w') as f:
        json.dump({'log': emu.jni_log, 'imports': {k: v for k, v in emu.calls.items()},
                   'properties': emu.props, 'emulator_strings': getattr(emu, 'emulator_props', [])}, f, indent=1)
    print('JNI calls:', len(emu.jni_log), 'imports:', dict(emu.calls))
    print('system properties queried:', emu.props[:40])
    for entry in emu.jni_log[:80]:
        print('  ', entry)
    return emu


if __name__ == '__main__':
    fn = sys.argv[1] if len(sys.argv) > 1 else 'JNI_OnLoad'
    run(func=fn)
