#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

void pad_key(const char *word, unsigned char *key) {
    int len = strlen(word);
    memset(key, '#', 16);
    if (len > 16) len = 16;
    memcpy(key, word, len);
}

int try_decrypt_with_flag(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *iv, unsigned char *key, unsigned char *plaintext, int disable_padding) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, plaintext_len = 0;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (disable_padding) {
        EVP_CIPHER_CTX_set_padding(ctx, 0);
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1; // decryption failed
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext[plaintext_len] = '\0';
    return plaintext_len;
}

unsigned char *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);
    unsigned char *buf = malloc(len > 0 ? len : 1);
    if (len > 0) fread(buf, 1, len, f);
    fclose(f);
    *out_len = len;
    return buf;
}

void print_hexdump_sample(unsigned char *buf, int len) {
    int n = len < 64 ? len : 64;
    for (int i = 0; i < n; ++i) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) putchar(c); else putchar('.');
    }
    putchar('\n');
}

int main(int argc, char *argv[]) {
    if (!(argc == 4 || argc == 5)) {
        printf("Usage:\n  %s <wordlist.txt> <cipher_with_prepended_iv.bin> <plaintext_ref.txt>\n", argv[0]);
        printf("or\n  %s <wordlist.txt> <cipher.bin> <iv.bin> <plaintext_ref.txt>\n", argv[0]);
        return 1;
    }

    const char *wordlist_path = argv[1];
    const char *cipher_path = argv[2];
    const char *iv_path = NULL;
    const char *plain_ref_path = NULL;
    int iv_prepended = 0;

    if (argc == 4) {
        plain_ref_path = argv[3];
        iv_prepended = 1;
    } else {
        iv_path = argv[3];
        plain_ref_path = argv[4];
        iv_prepended = 0;
    }

    FILE *words = fopen(wordlist_path, "r");
    if (!words) { perror("wordlist"); return 1; }

    long cipher_len = 0;
    unsigned char *cipher_buf = read_file(cipher_path, &cipher_len);
    if (!cipher_buf) { perror("cipherfile"); fclose(words); return 1; }

    unsigned char iv[16];
    unsigned char *ciphertext = NULL;
    long ciphertext_len = 0;

    if (iv_prepended) {
        if (cipher_len < 16) { fprintf(stderr, "cipher file too small to contain IV\n"); free(cipher_buf); fclose(words); return 1; }
        memcpy(iv, cipher_buf, 16);
        ciphertext = cipher_buf + 16;
        ciphertext_len = cipher_len - 16;
    } else {
        long iv_len = 0;
        unsigned char *iv_buf = read_file(iv_path, &iv_len);
        if (!iv_buf) { perror("ivfile"); free(cipher_buf); fclose(words); return 1; }
        if (iv_len < 16) { fprintf(stderr, "iv file must be at least 16 bytes\n"); free(iv_buf); free(cipher_buf); fclose(words); return 1; }
        memcpy(iv, iv_buf, 16);
        free(iv_buf);
        ciphertext = cipher_buf;
        ciphertext_len = cipher_len;
    }

    long ref_len = 0;
    unsigned char *ref_plain = read_file(plain_ref_path, &ref_len);
    if (!ref_plain) { perror("plaintext_ref"); free(cipher_buf); fclose(words); return 1; }
    unsigned char *ref_null = malloc(ref_len + 1);
    memcpy(ref_null, ref_plain, ref_len);
    ref_null[ref_len] = '\0';
    free(ref_plain);

    unsigned char key[16];
    unsigned char plaintext[8192];
    char word[256];
    int found = 0;

    while (fgets(word, sizeof(word), words)) {
        word[strcspn(word, "\r\n")] = 0;
        pad_key(word, key);

        int pt_len = try_decrypt_with_flag(ciphertext, (int)ciphertext_len, iv, key, plaintext, 0);
        if (pt_len > 0) {
            if (strncmp((char *)plaintext, (char *)ref_null, ref_len) == 0) {
                printf("[+] Found key (PKCS7): \"%s\"\n", word);
                found = 1; break;
            } else {
                printf("[?] Candidate key (PKCS7) : \"%s\" — decrypted (first 64 chars):\n", word);
                print_hexdump_sample(plaintext, pt_len);
                // continue searching
            }
        }

        pt_len = try_decrypt_with_flag(ciphertext, (int)ciphertext_len, iv, key, plaintext, 1);
        if (pt_len > 0) {
            if (strncmp((char *)plaintext, (char *)ref_null, ref_len) == 0) {
                printf("[+] Found key (NoPad): \"%s\"\n", word);
                found = 1; break;
            } else {
                printf("[?] Candidate key (NoPad) : \"%s\" — decrypted (first 64 chars):\n", word);
                print_hexdump_sample(plaintext, pt_len);
            }
        }
    }

    if (!found) printf("[-] Key not found.\n");

    free(ref_null);
    free(cipher_buf);
    fclose(words);
    return 0;
}
