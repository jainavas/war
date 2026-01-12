#!/usr/bin/env python3
"""
Visually Shocking C Obfuscator
Creates unreadable but compilable C code using confusing character combinations.
Fully reversible via mapping file.
"""

import re
import json
import sys
import os
import random
import argparse
from pathlib import Path
from typing import Dict, Set, Tuple, List

# Characters that look similar and are confusing to read
CONFUSING_CHARS = ['O', '0', 'l', '1', 'I', '_']

# C keywords and standard library - never obfuscate these
C_RESERVED = {
    # Keywords
    'auto', 'break', 'case', 'char', 'const', 'continue', 'default', 'do',
    'double', 'else', 'enum', 'extern', 'float', 'for', 'goto', 'if',
    'inline', 'int', 'long', 'register', 'restrict', 'return', 'short',
    'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef', 'union',
    'unsigned', 'void', 'volatile', 'while', '_Bool', '_Complex', '_Imaginary',
    # GCC Extensions
    '__asm__', 'asm', '__volatile__', '__inline__', '__attribute__',
    '__extension__', '__restrict__', '__alignof__', '__typeof__',
    # Types
    'size_t', 'ssize_t', 'ptrdiff_t', 'intptr_t', 'uintptr_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
    'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'bool', 'true', 'false', 'NULL', 'EOF',
    # Standard functions
    'main', 'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
    'scanf', 'fscanf', 'sscanf', 'getchar', 'putchar', 'puts', 'gets', 'fgets',
    'malloc', 'calloc', 'realloc', 'free', 'aligned_alloc',
    'memcpy', 'memmove', 'memset', 'memcmp', 'memchr',
    'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp',
    'strlen', 'strchr', 'strrchr', 'strstr', 'strtok', 'strdup',
    'strcspn', 'strspn', 'strpbrk', 'strnlen', 'strlcpy', 'strlcat',
    'strcasecmp', 'strncasecmp', 'strsep', 'strchrnul',
    'atoi', 'atol', 'atof', 'strtol', 'strtoul', 'strtod',
    'fopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell', 'rewind', 'fflush',
    'fgetc', 'fputc', 'fputs', 'feof', 'ferror', 'clearerr',
    'open', 'close', 'read', 'write', 'lseek', 'dup', 'dup2', 'pipe',
    'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv',
    'fork', 'exec', 'execve', 'execvp', 'wait', 'waitpid', 'exit', '_exit',
    'getpid', 'getppid', 'getuid', 'geteuid', 'setuid', 'seteuid',
    'kill', 'signal', 'sigaction', 'raise', 'alarm', 'pause',
    'mmap', 'munmap', 'mprotect', 'msync', 'mlock', 'munlock',
    'stat', 'fstat', 'lstat', 'chmod', 'chown', 'mkdir', 'rmdir', 'unlink',
    'opendir', 'readdir', 'closedir', 'getcwd', 'chdir',
    'time', 'clock', 'difftime', 'mktime', 'strftime', 'localtime', 'gmtime',
    'rand', 'srand', 'random', 'srandom', 'abs', 'labs',
    'qsort', 'bsearch', 'atexit', 'system', 'getenv', 'setenv',
    'assert', 'errno', 'perror', 'strerror',
    'ptrace', 'syscall',
    # ELF types
    'Elf32_Ehdr', 'Elf32_Phdr', 'Elf32_Shdr', 'Elf32_Sym', 'Elf32_Rel', 'Elf32_Rela',
    'Elf64_Ehdr', 'Elf64_Phdr', 'Elf64_Shdr', 'Elf64_Sym', 'Elf64_Rel', 'Elf64_Rela',
    # ELF constants
    'ELFMAG', 'SELFMAG', 'EI_CLASS', 'EI_DATA', 'EI_VERSION', 'EI_OSABI', 'EI_NIDENT',
    'ELFCLASS32', 'ELFCLASS64', 'ELFDATA2LSB', 'ELFDATA2MSB',
    'ET_NONE', 'ET_REL', 'ET_EXEC', 'ET_DYN', 'ET_CORE',
    'PT_NULL', 'PT_LOAD', 'PT_DYNAMIC', 'PT_INTERP', 'PT_NOTE', 'PT_PHDR',
    'PF_X', 'PF_W', 'PF_R',
    'SHT_NULL', 'SHT_PROGBITS', 'SHT_SYMTAB', 'SHT_STRTAB', 'SHT_RELA',
    'SHT_NOBITS', 'SHT_REL', 'SHT_DYNSYM',
    # Common macros
    'SEEK_SET', 'SEEK_CUR', 'SEEK_END',
    'O_RDONLY', 'O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'O_APPEND', 'O_EXCL',
    'PROT_NONE', 'PROT_READ', 'PROT_WRITE', 'PROT_EXEC',
    'MAP_SHARED', 'MAP_PRIVATE', 'MAP_ANONYMOUS', 'MAP_FIXED', 'MAP_FAILED',
    'S_ISREG', 'S_ISDIR', 'S_ISLNK', 'S_ISCHR', 'S_ISBLK', 'S_ISFIFO', 'S_ISSOCK',
    'S_IRUSR', 'S_IWUSR', 'S_IXUSR', 'S_IRGRP', 'S_IWGRP', 'S_IXGRP',
    'S_IROTH', 'S_IWOTH', 'S_IXOTH', 'S_IRWXU', 'S_IRWXG', 'S_IRWXO',
    'STDIN_FILENO', 'STDOUT_FILENO', 'STDERR_FILENO',
    'WIFEXITED', 'WEXITSTATUS', 'WIFSIGNALED', 'WTERMSIG', 'WIFSTOPPED', 'WSTOPSIG',
    'PTRACE_TRACEME', 'PTRACE_PEEKTEXT', 'PTRACE_PEEKDATA', 'PTRACE_PEEKUSER',
    'PTRACE_POKETEXT', 'PTRACE_POKEDATA', 'PTRACE_POKEUSER',
    'PTRACE_CONT', 'PTRACE_KILL', 'PTRACE_SINGLESTEP',
    'PTRACE_GETREGS', 'PTRACE_SETREGS', 'PTRACE_ATTACH', 'PTRACE_DETACH',
    'PTRACE_SYSCALL', 'PTRACE_SETOPTIONS', 'PTRACE_GETEVENTMSG',
    'PTRACE_O_EXITKILL', 'PTRACE_O_TRACESYSGOOD', 'PTRACE_O_TRACEFORK',
    'PTRACE_O_TRACEVFORK', 'PTRACE_O_TRACECLONE', 'PTRACE_O_TRACEEXEC',
    'PTRACE_O_TRACEVFORKDONE', 'PTRACE_O_TRACEEXIT',
    'SIGKILL', 'SIGSTOP', 'SIGCONT', 'SIGTERM', 'SIGINT', 'SIGHUP',
    'SIGCHLD', 'SIGSEGV', 'SIGBUS', 'SIGFPE', 'SIGPIPE', 'SIGALRM',
    'SIGTRAP', 'SIGABRT', 'SIGUSR1', 'SIGUSR2',
    'DT_NULL', 'DT_NEEDED', 'DT_STRTAB', 'DT_SYMTAB', 'DT_RELA', 'DT_RELASZ',
    # Preprocessor
    'define', 'include', 'ifdef', 'ifndef', 'endif', 'elif', 'undef', 'pragma',
    # ELF struct members (Elf64_Ehdr)
    'e_ident', 'e_type', 'e_machine', 'e_version', 'e_entry', 'e_phoff',
    'e_shoff', 'e_flags', 'e_ehsize', 'e_phentsize', 'e_phnum', 'e_shentsize',
    'e_shnum', 'e_shstrndx',
    # ELF struct members (Elf64_Phdr)
    'p_type', 'p_flags', 'p_offset', 'p_vaddr', 'p_paddr', 'p_filesz',
    'p_memsz', 'p_align',
    # ELF struct members (Elf64_Shdr)
    'sh_name', 'sh_type', 'sh_flags', 'sh_addr', 'sh_offset', 'sh_size',
    'sh_link', 'sh_info', 'sh_addralign', 'sh_entsize',
    # ELF struct members (Elf64_Sym)
    'st_name', 'st_info', 'st_other', 'st_shndx', 'st_value', 'st_size',
    # stat struct members
    'st_mode', 'st_ino', 'st_dev', 'st_nlink', 'st_uid', 'st_gid',
    'st_rdev', 'st_atime', 'st_mtime', 'st_ctime', 'st_blksize', 'st_blocks',
    # dirent struct members
    'd_name', 'd_ino', 'd_off', 'd_reclen', 'd_type',
    # Common types
    'mode_t', 'pid_t', 'uid_t', 'gid_t', 'off_t', 'dev_t', 'ino_t', 'nlink_t',
    'DIR', 'FILE', 'fd_set', 'dirent', 'user_regs_struct', 'siginfo_t',
    'sockaddr', 'sockaddr_in', 'sockaddr_un', 'timeval', 'timespec',
    # user_regs_struct members
    'orig_rax', 'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rip', 'eflags',
    # fchmod, fchown
    'fchmod', 'fchown',
}


class VisualObfuscator:
    def __init__(self, seed: int = None, name_length: int = 12):
        self.mapping: Dict[str, str] = {}
        self.reverse_mapping: Dict[str, str] = {}
        self.used_names: Set[str] = set()
        self.name_length = name_length
        if seed is not None:
            random.seed(seed)

    def _generate_confusing_name(self) -> str:
        """Generate a name using visually similar characters"""
        while True:
            # Start with underscore (valid C identifier start)
            # Then mix O/0, l/1/I to create visual confusion
            name = '_'
            for _ in range(self.name_length):
                name += random.choice(CONFUSING_CHARS)

            if name not in self.used_names and name not in C_RESERVED:
                self.used_names.add(name)
                return name

    def _extract_protected_regions(self, code: str) -> Tuple[str, Dict[str, str]]:
        """Extract strings, comments, and preprocessor directives"""
        placeholders = {}
        counter = [0]

        def make_placeholder(match):
            ph = f"__PH_{counter[0]:06d}__"
            placeholders[ph] = match.group(0)
            counter[0] += 1
            return ph

        # Order matters: process from most complex to simplest

        # Multi-line comments
        code = re.sub(r'/\*.*?\*/', make_placeholder, code, flags=re.DOTALL)

        # Single-line comments
        code = re.sub(r'//[^\n]*', make_placeholder, code)

        # String literals (handle escaped quotes)
        code = re.sub(r'"(?:[^"\\]|\\.)*"', make_placeholder, code)

        # Character literals
        code = re.sub(r"'(?:[^'\\]|\\.)*'", make_placeholder, code)

        # Preprocessor include with angle brackets
        code = re.sub(r'#\s*include\s*<[^>]+>', make_placeholder, code)

        return code, placeholders

    def _restore_protected_regions(self, code: str, placeholders: Dict[str, str]) -> str:
        """Restore protected regions"""
        for ph, original in placeholders.items():
            code = code.replace(ph, original)
        return code

    def _find_identifiers(self, code: str) -> Set[str]:
        """Find all identifiers to obfuscate"""
        # Match C identifiers
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\b'
        identifiers = set()

        for match in re.finditer(pattern, code):
            ident = match.group(1)
            # Skip reserved words and placeholders
            if ident not in C_RESERVED and not ident.startswith('__PH_'):
                identifiers.add(ident)

        return identifiers

    def _apply_obfuscation(self, code: str) -> str:
        """Replace identifiers with obfuscated names"""
        # Sort by length descending to avoid partial replacements
        sorted_idents = sorted(self.mapping.keys(), key=len, reverse=True)

        for original in sorted_idents:
            obfuscated = self.mapping[original]
            # Use word boundaries
            pattern = r'\b' + re.escape(original) + r'\b'
            code = re.sub(pattern, obfuscated, code)

        return code

    def _apply_deobfuscation(self, code: str) -> str:
        """Replace obfuscated names with original identifiers"""
        sorted_obf = sorted(self.reverse_mapping.keys(), key=len, reverse=True)

        for obfuscated in sorted_obf:
            original = self.reverse_mapping[obfuscated]
            pattern = r'\b' + re.escape(obfuscated) + r'\b'
            code = re.sub(pattern, original, code)

        return code

    def _minify_code(self, code: str) -> str:
        """Remove unnecessary whitespace while keeping code valid"""
        lines = code.split('\n')
        result_lines = []

        for line in lines:
            # Preserve preprocessor directives on their own lines
            stripped = line.strip()
            if stripped.startswith('#'):
                result_lines.append(stripped)
            elif stripped:
                # Collapse multiple spaces to single space
                collapsed = re.sub(r'[ \t]+', ' ', stripped)
                result_lines.append(collapsed)

        # Join with minimal newlines - keep preprocessor on separate lines
        result = []
        for line in result_lines:
            if line.startswith('#'):
                if result and not result[-1].endswith('\n'):
                    result.append('\n')
                result.append(line + '\n')
            else:
                result.append(line + ' ')

        return ''.join(result)

    def _remove_comments(self, code: str) -> str:
        """Strip all comments from code"""
        # Remove multi-line comments
        code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        # Remove single-line comments
        code = re.sub(r'//[^\n]*', '', code)
        return code

    def obfuscate(self, code: str, minify: bool = True, strip_comments: bool = True) -> str:
        """Obfuscate C code"""
        if strip_comments:
            code = self._remove_comments(code)

        # Extract protected regions
        code, placeholders = self._extract_protected_regions(code)

        # Find and map identifiers
        identifiers = self._find_identifiers(code)
        for ident in identifiers:
            if ident not in self.mapping:
                obf_name = self._generate_confusing_name()
                self.mapping[ident] = obf_name
                self.reverse_mapping[obf_name] = ident

        # Apply obfuscation
        code = self._apply_obfuscation(code)

        # Restore protected regions
        code = self._restore_protected_regions(code, placeholders)

        if minify:
            code = self._minify_code(code)

        return code

    def deobfuscate(self, code: str) -> str:
        """Deobfuscate C code"""
        code, placeholders = self._extract_protected_regions(code)
        code = self._apply_deobfuscation(code)
        code = self._restore_protected_regions(code, placeholders)
        return code

    def save_mapping(self, filepath: str):
        """Save mapping to JSON file"""
        data = {
            'mapping': self.mapping,
            'reverse_mapping': self.reverse_mapping,
            'name_length': self.name_length
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def load_mapping(self, filepath: str):
        """Load mapping from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        self.mapping = data['mapping']
        self.reverse_mapping = data['reverse_mapping']
        self.name_length = data.get('name_length', 12)
        self.used_names = set(self.mapping.values())


def fix_include_paths(code: str, include_dir: str, include_out_dir: str) -> str:
    """Replace include paths to point to obfuscated/deobfuscated headers"""
    # Replace patterns with both relative and direct paths
    code = code.replace(f'"{include_dir}/', f'"{include_out_dir}/')
    code = code.replace(f'"../{include_dir}/', f'"{include_out_dir}/')
    # Also handle the reverse direction (for deobfuscation)
    if include_dir == 'include_obfuscated' or include_out_dir == 'include':
        code = code.replace(f'"../{include_dir}/', f'"../include/')
        code = code.replace(f'"{include_dir}/', f'"include/')
    return code


def process_file(obfuscator: VisualObfuscator, input_path: str, output_path: str,
                 deobfuscate: bool = False, minify: bool = True, strip_comments: bool = True,
                 include_dir: str = 'include', include_out_dir: str = 'include_obfuscated'):
    """Process a single file"""
    with open(input_path, 'r', encoding='utf-8', errors='replace') as f:
        code = f.read()

    if deobfuscate:
        result = obfuscator.deobfuscate(code)
        # Reverse include path fix
        result = fix_include_paths(result, include_out_dir, include_dir)
    else:
        result = obfuscator.obfuscate(code, minify=minify, strip_comments=strip_comments)
        # Fix include paths to point to obfuscated headers
        result = fix_include_paths(result, include_dir, include_out_dir)

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(result)


def collect_all_files(directories: List[str]) -> List[Path]:
    """Collect all .c and .h files from multiple directories"""
    files = []
    for dir_path in directories:
        if os.path.isdir(dir_path):
            path = Path(dir_path)
            for ext in ['*.c', '*.h']:
                files.extend(path.glob(ext))
    return files


def scan_all_identifiers(obfuscator: VisualObfuscator, files: List[Path]):
    """First pass: scan all files to build complete mapping"""
    for file_path in files:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            code = f.read()

        # Remove comments for scanning
        code = obfuscator._remove_comments(code)
        code, _ = obfuscator._extract_protected_regions(code)
        identifiers = obfuscator._find_identifiers(code)

        # Build mapping for all identifiers
        for ident in identifiers:
            if ident not in obfuscator.mapping:
                obf_name = obfuscator._generate_confusing_name()
                obfuscator.mapping[ident] = obf_name
                obfuscator.reverse_mapping[obf_name] = ident


def process_directory(obfuscator: VisualObfuscator, input_dir: str, output_dir: str,
                      deobfuscate: bool = False, minify: bool = True, strip_comments: bool = True,
                      include_dir: str = 'include', include_out_dir: str = 'include_obfuscated'):
    """Process all .c and .h files in a directory"""
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    for ext in ['*.c', '*.h']:
        for src_file in input_path.glob(ext):
            dst_file = output_path / src_file.name
            process_file(obfuscator, str(src_file), str(dst_file),
                        deobfuscate, minify, strip_comments,
                        include_dir, include_out_dir)
            action = "Deobfuscated" if deobfuscate else "Obfuscated"
            print(f"  {action}: {src_file.name}")


def main():
    parser = argparse.ArgumentParser(
        description='Visually Shocking C Obfuscator - Makes code unreadable',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single-file mode (simple):
  %(prog)s obfuscate input.c output.c
  %(prog)s deobfuscate output.c restored.c --mapping mapping.json

  # Single-file with options:
  %(prog)s obfuscate input.c output.c --mapping custom.json --seed 42 --length 20

  # Directory mode (batch processing):
  %(prog)s obfuscate --src src --include include
  %(prog)s deobfuscate --src-out src_obfuscated --include-out include_obfuscated

  # Custom directories and options:
  %(prog)s obfuscate --src mysrc --include myinc --no-minify --seed 42
        """
    )

    parser.add_argument('mode', choices=['obfuscate', 'deobfuscate'],
                        help='Operation mode')

    # Positional arguments for single-file mode
    parser.add_argument('input_file', nargs='?', default=None,
                        help='Input file (single-file mode)')
    parser.add_argument('output_file', nargs='?', default=None,
                        help='Output file (single-file mode)')

    # Directory mode arguments
    parser.add_argument('--src', default='src',
                        help='Source directory (default: src)')
    parser.add_argument('--include', default='include',
                        help='Include directory (default: include)')
    parser.add_argument('--src-out', default='src_obfuscated',
                        help='Obfuscated source output (default: src_obfuscated)')
    parser.add_argument('--include-out', default='include_obfuscated',
                        help='Obfuscated include output (default: include_obfuscated)')

    # Common arguments
    parser.add_argument('--mapping', default=None,
                        help='Mapping file (default: auto-generated from output filename)')
    parser.add_argument('--seed', type=int, default=None,
                        help='Random seed for reproducible obfuscation')
    parser.add_argument('--length', type=int, default=12,
                        help='Length of obfuscated names (default: 12)')
    parser.add_argument('--no-minify', action='store_true',
                        help='Keep original formatting (no minification)')
    parser.add_argument('--keep-comments', action='store_true',
                        help='Keep comments in output')

    args = parser.parse_args()

    # Detect mode: single-file vs directory
    is_single_file_mode = args.input_file is not None and args.output_file is not None

    # Validate arguments
    if is_single_file_mode:
        # Single-file mode validation
        if not os.path.exists(args.input_file):
            print(f"Error: Input file not found: {args.input_file}")
            sys.exit(1)

        # Auto-generate mapping filename if not provided
        if args.mapping is None:
            # For obfuscate: output_file.mapping.json
            # For deobfuscate: input_file.mapping.json
            base_file = args.output_file if args.mode == 'obfuscate' else args.input_file
            args.mapping = f"{os.path.splitext(base_file)[0]}.mapping.json"

        # For deobfuscate, mapping must exist
        if args.mode == 'deobfuscate' and not os.path.exists(args.mapping):
            print(f"Error: Mapping file not found: {args.mapping}")
            print(f"Deobfuscation requires the mapping file generated during obfuscation")
            sys.exit(1)

    elif args.input_file is not None or args.output_file is not None:
        # Partially specified single-file mode
        print("Error: Both input_file and output_file are required for single-file mode")
        print("Usage: obfuscator.py obfuscate input.c output.c")
        sys.exit(1)
    else:
        # Directory mode - use default mapping if not provided
        if args.mapping is None:
            args.mapping = 'obfuscation_mapping.json'

    obfuscator = VisualObfuscator(seed=args.seed, name_length=args.length)
    minify = not args.no_minify
    strip_comments = not args.keep_comments

    # ========== SINGLE-FILE MODE ==========
    if is_single_file_mode:
        if args.mode == 'obfuscate':
            print(f"\n{'='*50}")
            print(f"  VISUAL OBFUSCATOR - Obfuscating Single File")
            print(f"{'='*50}\n")
            print(f"Input:   {args.input_file}")
            print(f"Output:  {args.output_file}")
            print(f"Mapping: {args.mapping}\n")

            # Read input file
            with open(args.input_file, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()

            # Obfuscate
            result = obfuscator.obfuscate(code, minify=minify, strip_comments=strip_comments)

            # Write output
            os.makedirs(os.path.dirname(args.output_file) or '.', exist_ok=True)
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(result)

            # Save mapping
            obfuscator.save_mapping(args.mapping)

            print(f"{'='*50}")
            print(f"  Obfuscation complete!")
            print(f"  - {len(obfuscator.mapping)} identifiers obfuscated")
            print(f"  - Output: {args.output_file}")
            print(f"  - Mapping: {args.mapping}")
            print(f"{'='*50}\n")

        else:  # deobfuscate
            print(f"\n{'='*50}")
            print(f"  VISUAL OBFUSCATOR - Deobfuscating Single File")
            print(f"{'='*50}\n")
            print(f"Input:   {args.input_file}")
            print(f"Output:  {args.output_file}")
            print(f"Mapping: {args.mapping}\n")

            # Load mapping
            obfuscator.load_mapping(args.mapping)

            # Read input file
            with open(args.input_file, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()

            # Deobfuscate
            result = obfuscator.deobfuscate(code)

            # Fix include paths back to original
            result = fix_include_paths(result, 'include_obfuscated', 'include')
            result = fix_include_paths(result, 'include_test_obf', 'include')
            result = fix_include_paths(result, 'include_obf', 'include')

            # Write output
            os.makedirs(os.path.dirname(args.output_file) or '.', exist_ok=True)
            with open(args.output_file, 'w', encoding='utf-8') as f:
                f.write(result)

            print(f"{'='*50}")
            print(f"  Deobfuscation complete!")
            print(f"  - {len(obfuscator.reverse_mapping)} identifiers restored")
            print(f"  - Output: {args.output_file}")
            print(f"{'='*50}\n")

        sys.exit(0)

    # ========== DIRECTORY MODE ==========
    if args.mode == 'obfuscate':
        print(f"\n{'='*50}")
        print("  VISUAL OBFUSCATOR - Obfuscating...")
        print(f"{'='*50}\n")

        # First pass: scan ALL files to build complete mapping
        print("Scanning all files to build identifier mapping...")
        all_files = collect_all_files([args.src, args.include])
        scan_all_identifiers(obfuscator, all_files)
        print(f"Found {len(obfuscator.mapping)} unique identifiers\n")

        # Second pass: apply obfuscation
        if os.path.isdir(args.src):
            print(f"Processing {args.src}/ -> {args.src_out}/")
            process_directory(obfuscator, args.src, args.src_out,
                            False, minify, strip_comments,
                            args.include, args.include_out)

        if os.path.isdir(args.include):
            print(f"\nProcessing {args.include}/ -> {args.include_out}/")
            process_directory(obfuscator, args.include, args.include_out,
                            False, minify, strip_comments,
                            args.include, args.include_out)

        # Save mapping
        obfuscator.save_mapping(args.mapping)

        print(f"\n{'='*50}")
        print(f"  Obfuscation complete!")
        print(f"  - {len(obfuscator.mapping)} identifiers obfuscated")
        print(f"  - Mapping saved to: {args.mapping}")
        print(f"{'='*50}\n")

    else:  # deobfuscate
        if not os.path.exists(args.mapping):
            print(f"Error: Mapping file not found: {args.mapping}")
            sys.exit(1)

        obfuscator.load_mapping(args.mapping)

        print(f"\n{'='*50}")
        print("  VISUAL OBFUSCATOR - Deobfuscating...")
        print(f"{'='*50}\n")

        # Reverse the directories for deobfuscation
        if os.path.isdir(args.src_out):
            print(f"Processing {args.src_out}/ -> {args.src}/")
            process_directory(obfuscator, args.src_out, args.src, True, False, False,
                            args.include, args.include_out)

        if os.path.isdir(args.include_out):
            print(f"\nProcessing {args.include_out}/ -> {args.include}/")
            process_directory(obfuscator, args.include_out, args.include, True, False, False,
                            args.include, args.include_out)

        print(f"\n{'='*50}")
        print(f"  Deobfuscation complete!")
        print(f"{'='*50}\n")


if __name__ == '__main__':
    main()
