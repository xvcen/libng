/*
 * loader.c — standalone harness for libng.so (arm64 Android).
 *
 * What it does:
 *   1) dlopen()s libng.so (constructors run -> runtime decryption of .data/.bss tables)
 *   2) calls every exported function with sane args
 *   3) brute-forces ng_ioctl(cmd,...) over a cmd range, surviving SIGSEGV/SIGALRM
 *      per call (sigsetjmp/siglongjmp), so a bad argument cannot kill the process
 *   4) periodically dumps the process image (module segments + heaps) to
 *      ngdump.bin + ngdump.json
 *
 * Build (in Termux):
 *   clang -O2 -fPIE -pie loader.c -o loader -ldl -llog
 * Run:
 *   LD_LIBRARY_PATH=/data/local/tmp/ng ./loader /data/local/tmp/ng/libng.so 0 0x400
 *
 * NOTE: libng.so needs libshadowhook.so + libc++_shared.so next to it.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <dlfcn.h>
#include <time.h>

static sigjmp_buf JB;
static volatile int in_call = 0;

static void on_fault(int sig) {
    if (in_call) { in_call = 0; siglongjmp(JB, sig); }
    _exit(100 + sig);
}
static void on_alarm(int sig) { on_fault(sig); }

/* ---------------- memory dump ---------------- */
typedef struct { uint64_t start, end; char perms[8]; char path[512]; } Region;

static int read_maps(Region **out) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    int cap = 256, n = 0;
    Region *r = malloc(sizeof(Region) * cap);
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        uint64_t a, b; char perms[8] = {0}, path[512] = {0};
        int got = sscanf(line, "%lx-%lx %7s %*s %*s %*s %511[^\n]", &a, &b, perms, path);
        if (got < 3) continue;
        if (n == cap) { cap *= 2; r = realloc(r, sizeof(Region) * cap); }
        r[n].start = a; r[n].end = b;
        strncpy(r[n].perms, perms, 7);
        strncpy(r[n].path, got >= 4 ? path : "", 511);
        n++;
    }
    fclose(f);
    *out = r;
    return n;
}

static int wanted(const Region *r, const char *mod_path) {
    if (strstr(r->path, "libng.so")) return 1;              /* module itself */
    if (strstr(r->path, "[heap]")) return 1;
    if (strstr(r->path, "libc_malloc")) return 1;           /* bionic malloc arena */
    if (r->path[0] == 0 && strchr(r->perms, 'w')) return 1; /* anon rw (junk tables) */
    return 0;
}

static void dump(const char *tag) {
    Region *regs; int n = read_maps(&regs);
    char bin[256], js[256];
    snprintf(bin, sizeof bin, "ngdump_%s.bin", tag);
    snprintf(js, sizeof js, "ngdump_%s.json", tag);
    FILE *fb = fopen(bin, "wb"), *fj = fopen(js, "w");
    if (!fb || !fj) { fprintf(stderr, "cannot write dump\n"); return; }
    fprintf(fj, "{\n \"regions\": [\n");
    unsigned long long total = 0;
    int first = 1;
    for (int i = 0; i < n; i++) {
        if (!wanted(&regs[i], NULL)) continue;
        size_t sz = regs[i].end - regs[i].start;
        unsigned char *buf = malloc(sz);
        if (!buf) continue;
        FILE *fm = fopen("/proc/self/mem", "rb");
        if (!fm) { free(buf); continue; }
        fseek(fm, (long)regs[i].start, SEEK_SET);
        size_t rd = fread(buf, 1, sz, fm);
        fclose(fm);
        if (rd != sz) { free(buf); continue; }
        if (!first) fprintf(fj, ",\n");
        first = 0;
        fprintf(fj, "  {\"start\": \"0x%llx\", \"size\": %zu, \"perms\": \"%s\", \"path\": \"%s\", \"file_off\": %llu}",
                (unsigned long long)regs[i].start, sz, regs[i].perms, regs[i].path,
                (unsigned long long)total);
        fwrite(buf, 1, sz, fb);
        total += sz;
        free(buf);
    }
    fprintf(fj, "\n ],\n \"total\": %llu,\n \"tag\": \"%s\"\n}\n", total, tag);
    fclose(fb); fclose(fj);
    free(regs);
    fprintf(stderr, "[+] dump: %s (%llu bytes)\n", js, total);
}

/* ---------------- exports ---------------- */
typedef int  (*fn2i)(void*, void*);
typedef long (*fn2p)(void*, long);
typedef int  (*fn1)(void*);
typedef long (*fn4)(long, void*, long, long);
typedef int  (*fn0)(void);
typedef int  (*fn_jnionload)(void*, void*);

static void (*g_cb)(void*, void*) = NULL;
static void dummy_cb(void *a, void *b) { (void)a; (void)b; }

int main(int argc, char **argv) {
    signal(SIGSEGV, on_fault); signal(SIGBUS, on_fault);
    signal(SIGILL, on_fault);  signal(SIGFPE, on_fault);
    signal(SIGALRM, on_alarm); signal(SIGABRT, on_fault);

    const char *path = argc > 1 ? argv[1] : "/data/local/tmp/ng/libng.so";
    long cmd_lo = argc > 2 ? strtol(argv[2], 0, 0) : 0;
    long cmd_hi = argc > 3 ? strtol(argv[3], 0, 0) : 0;

    void *h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }
    fprintf(stderr, "[+] loaded %s @ %p\n", path, h);

    dump("after_init");

    unsigned char scratch[4096];
    memset(scratch, 'A', sizeof scratch);

    fn2i register_callback = (fn2i)dlsym(h, "register_callback");
    fn2p set_player_token  = (fn2p)dlsym(h, "set_player_token");
    fn1  get_heartbeat    = (fn1)dlsym(h, "get_heartbeat_data");
    fn0  is_emulator      = (fn0)dlsym(h, "is_emulator");
    fn4  ng_ioctl         = (fn4)dlsym(h, "ng_ioctl");
    fprintf(stderr, "[+] syms: rc=%p tok=%p hb=%p emu=%p ioctl=%p\n",
            (void*)register_callback, (void*)set_player_token, (void*)get_heartbeat,
            (void*)is_emulator, (void*)ng_ioctl);

#define SAFE(label, expr)                                            \
    do {                                                             \
        in_call = 1;                                                 \
        alarm(3);                                                    \
        int j = sigsetjmp(JB, 1);                                    \
        if (j == 0) { expr; in_call = 0; alarm(0); }                 \
        else { fprintf(stderr, "[!] %s faulted (sig %d)\n", label, j); } \
        alarm(0);                                                    \
    } while (0)

    if (register_callback) SAFE("register_callback", register_callback((void*)dummy_cb, scratch));
    if (set_player_token)  SAFE("set_player_token",  set_player_token(scratch, 64));
    if (get_heartbeat)     SAFE("get_heartbeat_data", get_heartbeat(scratch));
    if (is_emulator)       SAFE("is_emulator",       printf("  is_emulator() = %d\n", is_emulator()));
    dump("after_api");

    if (ng_ioctl) {
        long n = 0;
        for (long cmd = cmd_lo; cmd < cmd_hi; cmd++) {
            in_call = 1; alarm(1);
            int j = sigsetjmp(JB, 1);
            if (j == 0) { ng_ioctl(cmd, scratch, 64, 0); in_call = 0; alarm(0); n++; }
            alarm(0);
            if ((cmd & 0x3f) == 0) { fprintf(stderr, "\r[+] ioctl %ld/0x%lx", cmd, cmd_hi); }
            if ((cmd & 0xfff) == 0) dump("brute");
        }
        fprintf(stderr, "\n[+] ioctl calls survived: %ld\n", n);
    }
    dump("final");
    fprintf(stderr, "[+] done; dumps: ngdump_*.json / ngdump_*.bin\n");
    return 0;
}
