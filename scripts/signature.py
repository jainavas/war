#!/usr/bin/env python3

# Clave real
KEY = b"42$$war$$"

# Ofuscar con XOR 0x42
obfuscated = [byte ^ 0x42 for byte in KEY]

print("// Clave RC4 ofuscada")
print("static const unsigned char OBFUSCATED_KEY[] = {")
print("    ", end="")
for i, byte in enumerate(obfuscated):
    print(f"0x{byte:02x}", end="")
    if i < len(obfuscated) - 1:
        print(", ", end="")
print()
print("};")
print(f"static const size_t KEY_LEN = {len(KEY)};")