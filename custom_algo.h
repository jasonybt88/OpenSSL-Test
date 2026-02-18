#ifndef CUSTOM_ALGO_H
#define CUSTOM_ALGO_H

// Stub customer algorithm interface.
// Current implementation uses AES-256-CBC as a placeholder.
int custom_algo_encrypt(const unsigned char *plaintext, int plaintext_len,
                        const unsigned char *key, int key_len,
                        const unsigned char *iv, int iv_len,
                        unsigned char *ciphertext);

int custom_algo_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                        const unsigned char *key, int key_len,
                        const unsigned char *iv, int iv_len,
                        unsigned char *plaintext);

#endif // CUSTOM_ALGO_H
