#include "custom_algo.h"
#include "encrypt.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>

#define HANDLE_CIPHER_ERROR(msg)       \
    do {                               \
        fprintf(stderr, "%s\n", msg);  \
        ERR_print_errors_fp(stderr);   \
        if (ctx) {                     \
            EVP_CIPHER_CTX_free(ctx);  \
        }                              \
        return -1;                     \
    } while (0)

int custom_algo_encrypt(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *key, int key_len,
                        const unsigned char *iv, int iv_len,
                        unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ciphertext_len = 0;

    if (key_len != SYM_KEY_SIZE || iv_len != SYM_IV_SIZE) {
        fprintf(stderr, "custom_algo_encrypt: invalid key/iv length\n");
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        HANDLE_CIPHER_ERROR("custom_algo_encrypt: EVP_CIPHER_CTX_new failed");
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        HANDLE_CIPHER_ERROR("custom_algo_encrypt: EVP_EncryptInit_ex failed");
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        HANDLE_CIPHER_ERROR("custom_algo_encrypt: EVP_EncryptUpdate failed");
    }
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        HANDLE_CIPHER_ERROR("custom_algo_encrypt: EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int custom_algo_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *key, int key_len,
                        const unsigned char *iv, int iv_len,
                        unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;

    if (key_len != SYM_KEY_SIZE || iv_len != SYM_IV_SIZE) {
        fprintf(stderr, "custom_algo_decrypt: invalid key/iv length\n");
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        HANDLE_CIPHER_ERROR("custom_algo_decrypt: EVP_CIPHER_CTX_new failed");
    }
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        HANDLE_CIPHER_ERROR("custom_algo_decrypt: EVP_DecryptInit_ex failed");
    }
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        HANDLE_CIPHER_ERROR("custom_algo_decrypt: EVP_DecryptUpdate failed");
    }
    plaintext_len = len;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        HANDLE_CIPHER_ERROR("custom_algo_decrypt: EVP_DecryptFinal_ex failed");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
