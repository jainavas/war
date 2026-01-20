#ifndef INFECTOR_H
#define INFECTOR_H

#include "config.h"
#include <stdbool.h>

// Forward declaration
typedef struct s_infector t_infector;

// Función que verifica si un archivo puede ser infectado por este infector
typedef bool (*can_infect_fn)(const char *filepath);

// Función que infecta el archivo
typedef int (*infect_fn)(const char *filepath, t_config *cfg);

struct s_infector {
    const char *name;           // Nombre descriptivo
    can_infect_fn can_infect;   // Función de detección
    infect_fn infect;           // Función de infección
    bool enabled;               // Si está habilitado
};

// Registro global de infectores
extern t_infector g_infectors[];
extern const int g_num_infectors;

// Motor de infección: itera sobre los infectores y usa el primero compatible
int infector_engine_run(const char *filepath, t_config *cfg);

// Helpers
const char *infector_get_type_name(const char *filepath);

#endif