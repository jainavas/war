#include "../include/war.h"

int main(void) {
    // 1. Anti-process check (sale si detecta proceso bloqueado)
    is_process_running("test");

    // 2. Ejecutar bajo ptrace - el hijo hace el trabajo real
    // Los syscalls custom serán interceptados por el padre
    run_with_tracer();
    
    // Este código nunca se ejecuta porque run_with_tracer
    // termina ambos procesos (padre e hijo)
    return 0;
}