#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <stdbool.h>

// Retorna true si detecta debugger activo
bool check_debugger(void);

// Retorna true si el proceso con nombre 'name' está corriendo
bool is_process_running(const char *name);

// Inicializa componentes anti-análisis (timers, etc)
void init_anti_debug(void);

#endif