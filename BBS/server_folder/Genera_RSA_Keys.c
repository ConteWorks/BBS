#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#include "../shared_folder/rsa.h"

int main() {
    // Genera la chiave RSA
    EVP_PKEY *rsa_keypair = generate_RSA_keypair();

    // Salva le chiavi su file
    save_RSA_key_to_file(rsa_keypair);
    
    // Libera la memoria
    EVP_PKEY_free(rsa_keypair);
    
    return 0;
}
