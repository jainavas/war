#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

typedef struct s_config {
    // Bonus flags
    bool enable_32bit;
    bool enable_recursive;
    bool enable_scripts;
    bool enable_packing;
    bool enable_backdoor;
    
    // Scanning config
    char **target_dirs;
    int num_dirs;
    int max_depth;        // Para recursión
    int max_files;        // Límite de archivos a infectar
    
    // Anti-analysis config
    bool check_debugger;
    bool check_process;
    char *blocked_process;  // Nombre del proceso a bloquear
    
    // Signature config
    bool modify_signature;  // Metamorphic behavior
    
} t_config;

// Inicializar con valores por defecto
t_config *config_create_default(void);
void config_destroy(t_config *cfg);

// Helpers
bool config_is_bonus_enabled(t_config *cfg);

#endif