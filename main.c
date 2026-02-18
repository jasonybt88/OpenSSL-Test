#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include "encrypt.h"

#define MAX_PATH_LEN 1024

typedef struct Crypto {
    unsigned char key[SYM_KEY_SIZE];
    unsigned char iv[SYM_IV_SIZE];
    int initialized;
} Crypto;

typedef struct RunStats {
    int total;
    int passed;
    int failed;
    int skipped;
} RunStats;

static void print_hex(const char *label, const unsigned char *buf, size_t len) {
    size_t i;
    printf("%s (len %lu): ", label, (unsigned long)len);
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

static int ends_with(const char *str, const char *suffix) {
    size_t str_len = 0;
    size_t suffix_len = 0;

    if (!str || !suffix) {
        return 0;
    }

    str_len = strlen(str);
    suffix_len = strlen(suffix);
    if (suffix_len > str_len) {
        return 0;
    }

    return strcmp(str + (str_len - suffix_len), suffix) == 0;
}

static int file_exists(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }
    fclose(fp);
    return 1;
}

static int join_path(char *out, size_t out_size, const char *dir, const char *name) {
    int wrote = 0;
    if (!out || !dir || !name) {
        return 0;
    }
    wrote = snprintf(out, out_size, "%s/%s", dir, name);
    return wrote > 0 && (size_t)wrote < out_size;
}

static int key_path_to_cert_path(const char *key_path, char *cert_path, size_t cert_path_size) {
    const char *suffix = "_key.pem";
    const char *replace = "_cert.pem";
    size_t key_len = 0;
    size_t suffix_len = 0;
    size_t base_len = 0;
    size_t replace_len = 0;

    if (!key_path || !cert_path) {
        return 0;
    }
    if (!ends_with(key_path, suffix)) {
        return 0;
    }

    key_len = strlen(key_path);
    suffix_len = strlen(suffix);
    replace_len = strlen(replace);
    base_len = key_len - suffix_len;

    if (base_len + replace_len + 1 > cert_path_size) {
        return 0;
    }

    memcpy(cert_path, key_path, base_len);
    memcpy(cert_path + base_len, replace, replace_len);
    cert_path[base_len + replace_len] = '\0';
    return 1;
}

static EVP_PKEY *try_load_private_key(const char *filename) {
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;

    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Unable to open private key file %s\n", filename);
        return NULL;
    }

    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pkey) {
        fprintf(stderr, "Error: Unable to read private key from file %s\n", filename);
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return pkey;
}

static EVP_PKEY *try_load_public_key_from_cert(const char *filename) {
    FILE *fp = NULL;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;

    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Unable to open certificate file %s\n", filename);
        return NULL;
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) {
        fprintf(stderr, "Error: Unable to read certificate from file %s\n", filename);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    pkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pkey) {
        fprintf(stderr, "Error: Unable to get public key from certificate %s\n", filename);
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return pkey;
}

static int derive_shared_secret(EVP_PKEY *local_private_key, EVP_PKEY *peer_public_key,
                                unsigned char **shared_secret, size_t *shared_secret_len) {
    EVP_PKEY_CTX *derive_ctx = NULL;

    if (!local_private_key || !peer_public_key || !shared_secret || !shared_secret_len) {
        return 0;
    }

    derive_ctx = EVP_PKEY_CTX_new(local_private_key, NULL);
    if (!derive_ctx) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (1 != EVP_PKEY_derive_init(derive_ctx)) {
        EVP_PKEY_CTX_free(derive_ctx);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (1 != EVP_PKEY_derive_set_peer(derive_ctx, peer_public_key)) {
        EVP_PKEY_CTX_free(derive_ctx);
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (1 != EVP_PKEY_derive(derive_ctx, NULL, shared_secret_len)) {
        EVP_PKEY_CTX_free(derive_ctx);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    *shared_secret = OPENSSL_malloc(*shared_secret_len);
    if (!*shared_secret) {
        EVP_PKEY_CTX_free(derive_ctx);
        return 0;
    }

    if (1 != EVP_PKEY_derive(derive_ctx, *shared_secret, shared_secret_len)) {
        EVP_PKEY_CTX_free(derive_ctx);
        ERR_print_errors_fp(stderr);
        OPENSSL_free(*shared_secret);
        *shared_secret = NULL;
        *shared_secret_len = 0;
        return 0;
    }

    EVP_PKEY_CTX_free(derive_ctx);
    return 1;
}

static int Crypto_Init(Crypto *crypto, const unsigned char *shared_secret, size_t shared_secret_len) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;

    if (!crypto || !shared_secret || shared_secret_len == 0) {
        return 0;
    }

    if (1 != EVP_Digest(shared_secret, shared_secret_len, digest, &digest_len, EVP_sha256(), NULL)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if (digest_len < SYM_KEY_SIZE) {
        return 0;
    }

    memcpy(crypto->key, digest, SYM_KEY_SIZE);
    if (1 != RAND_bytes(crypto->iv, SYM_IV_SIZE)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    crypto->initialized = 1;
    return 1;
}

static int is_sm2_key(EVP_PKEY *pkey) {
    char group_name[80];
    size_t group_name_len = 0;

    if (!pkey) {
        return 0;
    }

#ifdef EVP_PKEY_SM2
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_SM2) {
        return 1;
    }
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (1 == EVP_PKEY_get_group_name(pkey, group_name, sizeof(group_name), &group_name_len)) {
        if (strcmp(group_name, "SM2") == 0) {
            return 1;
        }
    }
#else
    (void)group_name;
    (void)group_name_len;
#endif

    return 0;
}

static int Crypto_Encrypt(const Crypto *crypto, const unsigned char *plaintext, int plaintext_len,
                          unsigned char *ciphertext, int *ciphertext_len) {
    int out_len = 0;

    if (!crypto || !crypto->initialized || !plaintext || plaintext_len < 0 || !ciphertext || !ciphertext_len) {
        return 0;
    }

    out_len = sym_encrypt(plaintext, plaintext_len,
                          crypto->key, SYM_KEY_SIZE,
                          crypto->iv, SYM_IV_SIZE,
                          ciphertext);
    if (out_len < 0) {
        return 0;
    }

    *ciphertext_len = out_len;
    return 1;
}

static int Crypto_Decrypt(const Crypto *crypto, const unsigned char *ciphertext, int ciphertext_len,
                          unsigned char *plaintext, int *plaintext_len) {
    int out_len = 0;

    if (!crypto || !crypto->initialized || !ciphertext || ciphertext_len < 0 || !plaintext || !plaintext_len) {
        return 0;
    }

    out_len = sym_decrypt(ciphertext, ciphertext_len,
                          crypto->key, SYM_KEY_SIZE,
                          crypto->iv, SYM_IV_SIZE,
                          plaintext);
    if (out_len < 0) {
        return 0;
    }

    *plaintext_len = out_len;
    return 1;
}

/* Returns: 1 pass, 0 fail, -1 skipped */
static int run_case(const char *key_file, const char *cert_file, int verbose) {
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    unsigned char *shared_secret_sender = NULL;
    size_t shared_secret_sender_len = 0;
    unsigned char *shared_secret_receiver = NULL;
    size_t shared_secret_receiver_len = 0;
    Crypto crypto = {0};
    const char *message = "This is a secret message to be encrypted using AES256!";
    const unsigned char *plaintext = (const unsigned char *)message;
    int plaintext_len = (int)strlen(message);
    int max_ciphertext_len = plaintext_len + SYM_IV_SIZE;
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    unsigned char *decryptedtext = NULL;
    int decryptedtext_len = 0;
    int key_type = 0;
    int rc = 0;

    private_key = try_load_private_key(key_file);
    public_key = try_load_public_key_from_cert(cert_file);
    if (!private_key || !public_key) {
        rc = 0;
        goto cleanup;
    }

    key_type = EVP_PKEY_base_id(private_key);
    if (key_type != EVP_PKEY_EC) {
        printf("SKIP: %s (unsupported key type for ECDH)\n", key_file);
        rc = -1;
        goto cleanup;
    }
    if (is_sm2_key(private_key)) {
        printf("SKIP: %s (SM2 key exchange not supported by this flow)\n", key_file);
        rc = -1;
        goto cleanup;
    }

    if (!derive_shared_secret(private_key, public_key, &shared_secret_sender, &shared_secret_sender_len)) {
        fprintf(stderr, "SKIP: derive_shared_secret sender unsupported for %s\n", key_file);
        rc = -1;
        goto cleanup;
    }
    if (!derive_shared_secret(private_key, public_key, &shared_secret_receiver, &shared_secret_receiver_len)) {
        fprintf(stderr, "SKIP: derive_shared_secret receiver unsupported for %s\n", key_file);
        rc = -1;
        goto cleanup;
    }

    if (shared_secret_sender_len != shared_secret_receiver_len ||
        CRYPTO_memcmp(shared_secret_sender, shared_secret_receiver, shared_secret_sender_len) != 0) {
        fprintf(stderr, "FAIL: shared secret mismatch for %s\n", key_file);
        rc = 0;
        goto cleanup;
    }

    if (!Crypto_Init(&crypto, shared_secret_sender, shared_secret_sender_len)) {
        fprintf(stderr, "FAIL: Crypto_Init for %s\n", key_file);
        rc = 0;
        goto cleanup;
    }

    ciphertext = OPENSSL_malloc((size_t)max_ciphertext_len);
    if (!ciphertext) {
        rc = 0;
        goto cleanup;
    }

    if (!Crypto_Encrypt(&crypto, plaintext, plaintext_len, ciphertext, &ciphertext_len)) {
        fprintf(stderr, "FAIL: Crypto_Encrypt for %s\n", key_file);
        rc = 0;
        goto cleanup;
    }

    decryptedtext = OPENSSL_malloc((size_t)ciphertext_len + 1);
    if (!decryptedtext) {
        rc = 0;
        goto cleanup;
    }
    memset(decryptedtext, 0, (size_t)ciphertext_len + 1);

    if (!Crypto_Decrypt(&crypto, ciphertext, ciphertext_len, decryptedtext, &decryptedtext_len)) {
        fprintf(stderr, "FAIL: Crypto_Decrypt for %s\n", key_file);
        rc = 0;
        goto cleanup;
    }

    if (decryptedtext_len != plaintext_len ||
        CRYPTO_memcmp(plaintext, decryptedtext, (size_t)plaintext_len) != 0) {
        fprintf(stderr, "FAIL: decrypted plaintext mismatch for %s\n", key_file);
        rc = 0;
        goto cleanup;
    }

    if (verbose) {
        print_hex("Symmetric key", crypto.key, SYM_KEY_SIZE);
        print_hex("IV", crypto.iv, SYM_IV_SIZE);
    }

    printf("PASS: %s\n", key_file);
    rc = 1;

cleanup:
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    OPENSSL_free(shared_secret_sender);
    OPENSSL_free(shared_secret_receiver);
    OPENSSL_free(ciphertext);
    OPENSSL_free(decryptedtext);
    return rc;
}

static void run_directory(const char *dir_path, RunStats *stats, int verbose) {
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char key_path[MAX_PATH_LEN];
    char cert_path[MAX_PATH_LEN];
    int rc = 0;

    if (!dir_path || !stats) {
        return;
    }

    dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "Warning: cannot open directory %s\n", dir_path);
        return;
    }

    printf("\nScanning directory: %s\n", dir_path);
    while ((entry = readdir(dir)) != NULL) {
        if (!ends_with(entry->d_name, "_key.pem")) {
            continue;
        }

        if (!join_path(key_path, sizeof(key_path), dir_path, entry->d_name)) {
            fprintf(stderr, "Warning: path too long for key file %s/%s\n", dir_path, entry->d_name);
            continue;
        }
        if (!key_path_to_cert_path(key_path, cert_path, sizeof(cert_path))) {
            fprintf(stderr, "Warning: could not map cert path from key %s\n", key_path);
            continue;
        }
        if (!file_exists(cert_path)) {
            fprintf(stderr, "SKIP: cert not found for key %s\n", key_path);
            stats->skipped++;
            continue;
        }

        stats->total++;
        rc = run_case(key_path, cert_path, verbose);
        if (rc > 0) {
            stats->passed++;
        } else if (rc < 0) {
            stats->skipped++;
        } else {
            stats->failed++;
        }
    }

    closedir(dir);
}

int main(void) {
    RunStats stats = {0};
    const char *dirs_to_scan[] = {".", "old certs", "matrix_certs"};
    size_t i = 0;

    printf("Starting cert loop for ECC + symmetric crypto flow...\n");

    for (i = 0; i < sizeof(dirs_to_scan) / sizeof(dirs_to_scan[0]); i++) {
        run_directory(dirs_to_scan[i], &stats, 0);
    }

    printf("\nSummary:\n");
    printf("  total=%d\n", stats.total);
    printf("  passed=%d\n", stats.passed);
    printf("  failed=%d\n", stats.failed);
    printf("  skipped=%d\n", stats.skipped);

    if (stats.failed > 0) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
