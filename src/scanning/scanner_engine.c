#include "../../include/scanner.h"
#include "../../include/war.h"
#include <stdio.h>

bool is_elf64_file(const char *filepath)
{
	int fd;
	unsigned char magic[4];
	ssize_t bytes_read;
	fd = custom_open(filepath, O_RDONLY);
	if (fd < 0)
		return false;
	bytes_read = read(fd, magic, 4);
	custom_close(fd);
	if (bytes_read != 4)
		return false;
	return (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F');
}

int scanner_engine_run(scan_strategy_t strategy, t_config *cfg, scan_callback_fn callback) {
    if (!cfg || !callback) return -1;
    
    switch (strategy) {
        case SCAN_STRATEGY_SIMPLE:
            return scanner_simple(cfg, callback);
        
        case SCAN_STRATEGY_RECURSIVE:
            if (!cfg->enable_recursive) {
                // Fallback a simple si no está habilitado
                return scanner_simple(cfg, callback);
            }
            return scanner_recursive(cfg, callback);
        
        default:
            return -1;
    }
}

int scanner_simple(t_config *cfg, scan_callback_fn callback) {
    // Escanear solo los directorios especificados en cfg->target_dirs
    for (int i = 0; i < cfg->num_dirs; i++) {
        DIR *dir = opendir(cfg->target_dirs[i]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || 
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", 
                     cfg->target_dirs[i], entry->d_name);
            
            struct stat st;
            if (stat(filepath, &st) < 0) continue;
            if (!S_ISREG(st.st_mode)) continue;  // Solo archivos regulares
            
            // Llamar al callback para procesar el archivo
            callback(filepath, cfg);
        }
        
        closedir(dir);
    }
    
    return 0;
}

int scanner_recursive(t_config *cfg, scan_callback_fn callback) {
    // BONUS 2: implementar después
    // Por ahora, fallback a simple
    return scanner_simple(cfg, callback);
}