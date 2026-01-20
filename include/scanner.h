#ifndef SCANNER_H
#define SCANNER_H

#include "config.h"

typedef enum {
    SCAN_STRATEGY_SIMPLE,      // Solo directorios especificados (actual)
    SCAN_STRATEGY_RECURSIVE,   // BONUS 2: recursivo desde raíz
} scan_strategy_t;

// Callback llamado por el scanner para cada archivo encontrado
typedef void (*scan_callback_fn)(const char *filepath, t_config *cfg);

// Motor de escaneo
int scanner_engine_run(scan_strategy_t strategy, t_config *cfg, scan_callback_fn callback);

// Implementaciones específicas
int scanner_simple(t_config *cfg, scan_callback_fn callback);
int scanner_recursive(t_config *cfg, scan_callback_fn callback);

#endif