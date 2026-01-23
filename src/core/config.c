#include "../../include/config.h"
#include <stdlib.h>
#include <string.h>

t_config *config_create_default(void) {
    t_config *cfg = calloc(1, sizeof(t_config));
    if (!cfg) return NULL;
    
    // Bonus disabled por defecto
    cfg->enable_32bit = true;
    cfg->enable_recursive = false;
    cfg->enable_scripts = false;
    cfg->enable_packing = false;
    cfg->enable_backdoor = false;
    
    // Directorios por defecto (Famine/Pestilence/War)
    cfg->target_dirs = malloc(2 * sizeof(char *));
    if (!cfg->target_dirs) {
        free(cfg);
        return NULL;
    }
    cfg->target_dirs[0] = strdup("/tmp/test");
    cfg->target_dirs[1] = strdup("/tmp/test2");
    cfg->num_dirs = 2;
    
    // Límites por defecto
    cfg->max_depth = 10;      // Profundidad recursiva
    cfg->max_files = 100;     // Máximo de archivos a infectar
    
    // Anti-analysis habilitado
    cfg->check_debugger = true;
    cfg->check_process = true;
    cfg->blocked_process = strdup("test");
    
    // Metamorphic habilitado (para War)
    cfg->modify_signature = true;
    
    return cfg;
}

void config_destroy(t_config *cfg) {
    if (!cfg) return;
    
    if (cfg->target_dirs) {
        for (int i = 0; i < cfg->num_dirs; i++) {
            free(cfg->target_dirs[i]);
        }
        free(cfg->target_dirs);
    }
    
    free(cfg->blocked_process);
    free(cfg);
}

bool config_is_bonus_enabled(t_config *cfg) {
    if (!cfg) return false;
    return cfg->enable_32bit || cfg->enable_recursive || 
           cfg->enable_scripts || cfg->enable_packing || 
           cfg->enable_backdoor;
}