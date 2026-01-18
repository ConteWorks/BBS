#if !defined(HASH_H)
#define HASH_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#if !defined(SALT_LEN)
#define SALT_LEN 16  // Lunghezza del salt in byte
#endif

#if !defined(HASH_LEN)
#define HASH_LEN 32  // Lunghezza dell'hash (SHA-256 restituisce 32 byte)
#endif

/* Funzione per generare salt */
int generate_salt(unsigned char* salt, int salt_len) {
    // Genera salt casuale
    if (RAND_bytes(salt, salt_len) != 1) {
        printf("Errore nella generazione del salt\n");
        return 0;
    }
    return 1;
}

/* Funzione per hashare la password con salt */
int hash_password(const char* password, const unsigned char* salt, int salt_len, unsigned char* digest, int* digest_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("Errore nella creazione del contesto hash\n");
        return 0;
    }

    // Inizializza il contesto per SHA-256
    if (EVP_DigestInit(ctx, EVP_sha256()) != 1) {
        printf("Errore nell'inizializzazione del digest\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Aggiunge il salt
    if (EVP_DigestUpdate(ctx, salt, salt_len) != 1) {
        printf("Errore nell'aggiornamento con salt\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Aggiunge la password
    if (EVP_DigestUpdate(ctx, password, strlen(password)) != 1) {
        printf("Errore nell'aggiornamento con password\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Finalizza e ottiene l'hash
    if (EVP_DigestFinal(ctx, digest, (unsigned int*)digest_len) != 1) {
        printf("Errore nella finalizzazione del digest\n");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Libera il contesto
    EVP_MD_CTX_free(ctx);
    return 1;
}

/* Funzione per confrontare gli hash usando CRYPTO_memcmp per evitare attacchi di timing */
int verify_password(const unsigned char* stored_hash, const unsigned char* computed_hash, int hash_len) {
    // Confronta gli hash in modo sicuro
    if (CRYPTO_memcmp(stored_hash, computed_hash, hash_len) == 0) {
        return 1;  // Hash uguali, password corretta
    } else {
        return 0;  // Hash diversi, password errata
    }
}

/* Funzione per confrontare le password usando CRYPTO_memcmp per evitare attacchi di timing */
int verify_password_with_salt(const char *password, const char *salt_hex, const char *stored_hash_hex) {
    unsigned char salt[SALT_LEN];
    unsigned char hash[HASH_LEN];
    int hash_len = 0;

    // Converti il salt_hex in byte
    for (int i = 0; i < SALT_LEN; i++) {
        sscanf(&salt_hex[i * 2], "%2hhx", &salt[i]);
    }

    // Genera l'hash della password con il salt fornito
    if (!hash_password(password, salt, SALT_LEN, hash, &hash_len)) {
        printf("Errore nell'hash della password durante la verifica.\n");
        return 0; // Errore
    }

    // Converti l'hash calcolato in stringa esadecimale
    char hash_hex[HASH_LEN * 2 + 1];
    for (int i = 0; i < HASH_LEN; i++) {
        snprintf(&hash_hex[i * 2], 3, "%02x", hash[i]);
    }

    // Usa CRYPTO_memcmp per confrontare gli hash in modo costante
    if (CRYPTO_memcmp(hash_hex, stored_hash_hex, HASH_LEN * 2) == 0) {
        return 1; // Password corretta
    } else {
        return 0; // Password errata
    }
}
#endif /* HASH_H */
