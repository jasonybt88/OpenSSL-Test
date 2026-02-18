#ifndef ENCRYPT_H
#define ENCRYPT_H

#define SYM_KEY_SIZE 32
#define SYM_IV_SIZE 16

// Generic symmetric interface backed by customer algorithm implementation.
// Returns output length on success, -1 on failure.
int sym_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, int key_len,
                const unsigned char *iv, int iv_len,
                unsigned char *ciphertext);

int sym_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, int key_len,
                const unsigned char *iv, int iv_len,
                unsigned char *plaintext);

#endif // ENCRYPT_H
