#if !defined(RSA_H)
#define RSA_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

EVP_PKEY *generate_RSA_keypair() {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        handle_errors();

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        handle_errors();

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        handle_errors();

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        handle_errors();

    EVP_PKEY_CTX_free(ctx);  // Liberazione della memoria
    return pkey;
}

int save_RSA_key_to_file(EVP_PKEY *pkey) {
    FILE *priv_file = fopen("server_folder/private_key.pem", "wb");
    if (!priv_file) {
        perror("Unable to open private key file for writing");
        return -1;
    }

    FILE *pub_file = fopen("shared_folder/public_key.pem", "wb");
    if (!pub_file) {
        perror("Unable to open public key file for writing");
        fclose(priv_file);
        return -1;
    }

    if (!PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(priv_file);
        fclose(pub_file);
        handle_errors();
    }

    if (!PEM_write_PUBKEY(pub_file, pkey)) {
        fclose(priv_file);
        fclose(pub_file);
        handle_errors();
    }

    fclose(priv_file);
    fclose(pub_file);
    return 0;
}

EVP_PKEY *load_private_RSA_key(const char *filename) {
    FILE *priv_file = fopen(filename, "rb");
    if (!priv_file) {
        perror("Unable to open private key file for reading");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);

    if (!pkey)
        handle_errors();

    return pkey;
}

EVP_PKEY *load_public_RSA_key(const char *filename) {
    FILE *pub_file = fopen(filename, "rb");
    if (!pub_file) {
        perror("Unable to open public key file for reading");
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);

    if (!pkey)
        handle_errors();

    return pkey;
}

int encrypt_RSA(EVP_PKEY *pub_key, const unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    if (!pub_key || !plaintext || !ciphertext) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t outlen;
    if (EVP_PKEY_encrypt(ctx, NULL, &outlen, plaintext, plaintext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_encrypt(ctx, ciphertext, &outlen, plaintext, plaintext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

int decrypt_RSA(EVP_PKEY *priv_key, const unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    if (!priv_key || !ciphertext || !plaintext) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, ciphertext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_decrypt(ctx, plaintext, &outlen, ciphertext, ciphertext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return outlen;
}

#endif /* RSA_H */


