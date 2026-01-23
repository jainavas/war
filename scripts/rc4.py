#!/usr/bin/env python3
# Regenerar signature

def rc4_crypt(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    result = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)

# Clave RC4 (después de XOR 0x42)
OBFUSCATED_KEY = bytes([0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66])
key = bytes([b ^ 0x42 for b in OBFUSCATED_KEY])

# Firma SIN el [%08X] al final
plaintext = b"<<<WAR_SIG>>> War version 1.0 (c)oded by jainavas - jvidal-t - "

# Encriptar
encrypted = rc4_crypt(plaintext, key)

# Imprimir en formato C
print("unsigned char ENCRYPTED_BASE_SIG[] = {")
for i in range(0, len(encrypted), 8):
    chunk = encrypted[i:i+8]
    hex_str = ', '.join(f'0x{b:02x}' for b in chunk)
    print(f"    {hex_str},")
print("};")
print(f"static const size_t BASE_SIG_LEN = {len(encrypted)};")