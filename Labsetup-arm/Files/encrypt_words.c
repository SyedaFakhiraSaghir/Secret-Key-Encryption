#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <openssl/evp.h>

static unsigned char hexchar2byte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return 0;
}

static unsigned char *hex_to_bytes(const char *hex, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return NULL;
    *out_len = len / 2;
    unsigned char *buf = malloc(*out_len);
    for (size_t i = 0; i < *out_len; ++i) {
        buf[i] = (hexchar2byte(hex[2*i]) << 4) | hexchar2byte(hex[2*i + 1]);
    }
    return buf;
}

int encrypt_aes_128_cbc(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *key, const unsigned char *iv,
                        unsigned char **ciphertext, int *cipher_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len;
    int ciphertext_len_alloc = plaintext_len + EVP_CIPHER_block_size(EVP_aes_128_cbc());
    unsigned char *out = malloc(ciphertext_len_alloc);
    if (!out) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    if (1 != EVP_EncryptUpdate(ctx, out, &len, plaintext, plaintext_len)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    int total_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, out + len, &len)) {
        free(out);
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;

    *ciphertext = out;
    *cipher_len = total_len;

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

static void trim_newline(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == '\n' || s[n-1] == '\r')) {
        s[n-1] = '\0';
        --n;
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s wordlist.txt plaintext_file target_cipher_hex\n", argv[0]);
        return 1;
    }

    const char *wordlist_path = argv[1];
    const char *plaintext_path = argv[2];
    const char *target_hex = argv[3];

    // read plaintext bytes exactly (do not append newline)
    FILE *pf = fopen(plaintext_path, "rb");
    if (!pf) { perror("opening plaintext file"); return 1; }
    fseek(pf, 0, SEEK_END);
    long plaintext_len = ftell(pf);
    fseek(pf, 0, SEEK_SET);
    if (plaintext_len < 0) { perror("ftell"); fclose(pf); return 1; }
    unsigned char *plaintext = malloc(plaintext_len);
    if (!plaintext) { fclose(pf); return 1; }
    if (fread(plaintext, 1, plaintext_len, pf) != (size_t)plaintext_len) {
        perror("reading plaintext");
        free(plaintext);
        fclose(pf);
        return 1;
    }
    fclose(pf);

    // parse target cipher hex
    size_t target_len;
    unsigned char *target = hex_to_bytes(target_hex, &target_len);
    if (!target) { fprintf(stderr, "Invalid target hex\n"); free(plaintext); return 1; }

    // fixed IV given in the problem
    const char *iv_hex = "aabbccddeeff00998877665544332211";
    size_t iv_len;
    unsigned char *iv = hex_to_bytes(iv_hex, &iv_len);
    if (!iv || iv_len != 16) { fprintf(stderr, "Invalid IV\n"); free(plaintext); free(target); return 1; }

    FILE *wf = fopen(wordlist_path, "r");
    if (!wf) { perror("opening wordlist"); free(plaintext); free(target); free(iv); return 1; }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), wf)) {
        trim_newline(line);
        // skip empty lines
        if (line[0] == '\0') continue;
        size_t wlen = strlen(line);
        if (wlen > 16) continue; // word longer than 16 chars - skip

        // prepare key: copy word and pad with '#'
        unsigned char key[16];
        memset(key, '#', 16);
        memcpy(key, (unsigned char*)line, wlen);

        // encrypt
        unsigned char *ciphertext = NULL;
        int cipher_len = 0;
        if (!encrypt_aes_128_cbc(plaintext, (int)plaintext_len, key, iv, &ciphertext, &cipher_len)) {
            fprintf(stderr, "Encryption error for word '%s'\n", line);
            continue;
        }

        // compare lengths first
        if ((size_t)cipher_len == target_len && memcmp(ciphertext, target, target_len) == 0) {
            printf("FOUND key word: '%s'\n", line);
            printf("Full 16-byte key (hex): ");
            for (int i = 0; i < 16; ++i) printf("%02x", key[i]);
            printf("\n");
            found = 1;
            free(ciphertext);
            break;
        }

        free(ciphertext);
    }

    if (!found) {
        printf("No matching key found in wordlist.\n");
    }

    free(plaintext);
    free(target);
    free(iv);
    fclose(wf);
    return 0;
}
