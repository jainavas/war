#!/bin/bash

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Building 32-bit metamorph shellcode...${NC}"

# Compilar shellcode 32-bit
# -fno-pic: evitar código position-independent que genera calls a __x86.get_pc_thunk
# -fno-pie: no generar ejecutable PIE
# -Os: optimizar por tamaño - minimiza código y evita duplicar bloques de salida
# -fomit-frame-pointer: reducir uso del stack
gcc -m32 -nostdlib -fno-pic -fno-pie -fno-stack-protector -z execstack \
    -Os -fomit-frame-pointer -ffreestanding \
    -o obj/metamorph_32.o \
    -c src/metamorph/metamorph_32.c

# Extraer sección .metamorph
objcopy -O binary --only-section=.metamorph \
    obj/metamorph_32.o obj/metamorph_32.bin

# Convertir a header C
echo "// Auto-generated from metamorph_32.c" > include/metamorph_shellcode_x86.h
echo "#ifndef METAMORPH_SHELLCODE_X86_H" >> include/metamorph_shellcode_x86.h
echo "#define METAMORPH_SHELLCODE_X86_H" >> include/metamorph_shellcode_x86.h
echo "" >> include/metamorph_shellcode_x86.h

# Calcular offset del entry point (metamorph_mutate_self_x86)
ENTRY_OFFSET=$(nm obj/metamorph_32.o | grep metamorph_mutate_self_x86 | awk '{print "0x" $1}')
echo "#define METAMORPH_ENTRY_OFFSET_X86 $ENTRY_OFFSET" >> include/metamorph_shellcode_x86.h
echo "" >> include/metamorph_shellcode_x86.h

# Tamaño del shellcode
SIZE=$(stat -c%s obj/metamorph_32.bin)
echo "#define METAMORPH_SHELLCODE_SIZE_X86 $SIZE" >> include/metamorph_shellcode_x86.h
echo "" >> include/metamorph_shellcode_x86.h

# Array con los bytes
echo "static const unsigned char metamorph_shellcode_x86[] = {" >> include/metamorph_shellcode_x86.h
xxd -i obj/metamorph_32.bin | grep '0x' | sed 's/^[ ]*//' >> include/metamorph_shellcode_x86.h
echo "};" >> include/metamorph_shellcode_x86.h
echo "" >> include/metamorph_shellcode_x86.h
echo "#endif" >> include/metamorph_shellcode_x86.h

echo -e "${GREEN}✓ 32-bit shellcode generated (${SIZE} bytes, entry at ${ENTRY_OFFSET})${NC}"