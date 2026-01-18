#if !defined(AES_H)
#define AES_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#if !defined(AES_KEY_SIZE)
#define AES_KEY_SIZE 32  // Dimensione della chiave in byte (AES-256)[32 byte = 256 bit]
#endif 

#if !defined (AES_BLOCK_SIZE)
#define AES_BLOCK_SIZE 16  // Dimensione del blocco AES (16 byte)
#endif

// Funzione per generare una chiave AES casuale
int generate_aes_key(unsigned char *key, unsigned char *iv) {
    // Genera una chiave casuale
    if (!RAND_bytes(key, AES_KEY_SIZE)) {
        fprintf(stderr, "Errore nella generazione della chiave AES\n");
        return 0;
    }
    // Genera un IV casuale
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Errore nella generazione dell'IV\n");
        return 0;
    }
    return 1;
}

// Funzione per crittografare i dati
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Crea e inizializza il contesto
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Errore nella creazione del contesto\n");
        return -1;
    }

    // Inizializza la crittografia AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Errore nell'inizializzazione della crittografia\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Crittografa i dati
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        fprintf(stderr, "Errore durante la crittografia\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalizza la crittografia
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Errore durante la finalizzazione della crittografia\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Libera il contesto
    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    
    return ciphertext_len;
}

// Funzione per decrittografare i dati
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Crea e inizializza il contesto
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Errore nella creazione del contesto\n");
        return -1;
    }

    // Inizializza la decrittografia AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Errore nell'inizializzazione della decrittografia\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decrittografa i dati
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        fprintf(stderr, "Errore durante la decrittografia\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Finalizza la decrittografia
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Errore durante la finalizzazione della decrittografia\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    // Libera il contesto
    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    
    return plaintext_len;
}

#endif /* AES_H */
