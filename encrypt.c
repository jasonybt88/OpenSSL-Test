#include "encrypt.h"
#include "custom_algo.h"

int sym_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, int key_len,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext) {
    return custom_algo_encrypt(plaintext, plaintext_len, key, key_len, iv, iv_len, ciphertext);
}

int sym_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, int key_len,
                const unsigned char *iv, int iv_len,
                unsigned char *plaintext) {
    return custom_algo_decrypt(ciphertext, ciphertext_len, key, key_len, iv, iv_len, plaintext);
}
