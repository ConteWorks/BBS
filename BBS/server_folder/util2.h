#if !defined(UTIL_H2)
#define UTIL_H2

#include "../server_folder/hash.h"

// Funzione che riscrive il body come email::nickname::salt::hash_password
int rewrite_body(char *body, char *email, char *nickname, char *password) {
    // Controlla che email, nickname e password non siano vuoti
    if (email == NULL || email[0] == '\0') {
        printf("Errore: email vuota.\n");
        return 0; // Errore
    }
    if (nickname == NULL || nickname[0] == '\0') {
        printf("Errore: nickname vuoto.\n");
        return 0; // Errore
    }
    if (password == NULL || password[0] == '\0') {
        printf("Errore: password vuota.\n");
        return 0; // Errore
    }

    memset(body, '\0', BUFFER_SIZE); // Azzera il buffer 'body'
    
    unsigned char salt[SALT_LEN];
    unsigned char hash[HASH_LEN];
    int hash_len = 0;

    // Genera il salt
    if (!generate_salt(salt, SALT_LEN)) {
        printf("Errore nella generazione del salt.\n");
        return 0; // Errore
    }

    // Genera l'hash della password con il salt
    if (!hash_password(password, salt, SALT_LEN, hash, &hash_len)) {
        printf("Errore nell'hash della password.\n");
        return 0; // Errore
    }

    // Converti il salt in stringa esadecimale
    char salt_hex[SALT_LEN * 2 + 1];
    for (int i = 0; i < SALT_LEN; i++) {
        snprintf(&salt_hex[i * 2], 3, "%02x", salt[i]); // Converti byte per byte in esadecimale
    }

    // Converti l'hash in stringa esadecimale
    char hash_hex[HASH_LEN * 2 + 1];
    for (int i = 0; i < HASH_LEN; i++) {
        snprintf(&hash_hex[i * 2], 3, "%02x", hash[i]); // Converti byte per byte in esadecimale
    }

    char body1[medium_size] = {0};
    char body2[large_size] = {0};

    // Concatena i risultati nel body
    myconcat(body1, BUFFER_SIZE, email, "::", nickname);   // email::nickname
    myconcat(body2, BUFFER_SIZE, body1, "::", salt_hex);    // email::nickname::salt
    myconcat(body, BUFFER_SIZE, body2, "::", hash_hex);     // email::nickname::salt::hash_password

    return 1; // Successo
}


void bytes_to_hex(const unsigned char *bytes, int byte_len, char *hex_output, int hex_output_len) {
    if (hex_output_len < (byte_len * 2 + 1)) {
        fprintf(stderr, "Buffer esadecimale troppo piccolo\n");
        return;
    }
    for (int i = 0; i < byte_len; i++) {
        sprintf(&hex_output[i * 2], "%02x", bytes[i]);
    }
    hex_output[byte_len * 2] = '\0'; // Terminatore della stringa
}

// Separa i vari campi del body e li salva nei rispettivi output
int split_body(const char *body, char *email, char *nickname, char *salt_hex, char *hash_hex) {
    // Inizializza i buffer come stringhe vuote
    email[0] = '\0';
    nickname[0] = '\0';
    salt_hex[0] = '\0';
    hash_hex[0] = '\0';

    char temp_body[BUFFER_SIZE];
    char remaining_body[BUFFER_SIZE];

    // Fase 1: Estrai email
    if (!split_in_two(body, "::", email, temp_body, small_size, BUFFER_SIZE)) {
        printf("Errore nello split di email.\n");
        return 0;
    }

    // Fase 2: Estrai nickname
    if (!split_in_two(temp_body, "::", nickname, remaining_body, small_size, BUFFER_SIZE)) {
        printf("Errore nello split di nickname.\n");
        return 0;
    }

    // Fase 3: Estrai salt_hex
    if (!split_in_two(remaining_body, "::", salt_hex, hash_hex, SALT_LEN * 2 + 1, HASH_LEN * 2 + 1)) {
        printf("Errore nello split di salt_hex.\n");
        return 0;
    }
    // Tutto è stato splittato correttamente
    
    // Controlla che i campi non siano vuoti
    if (email == NULL || email[0] == '\0') {
        printf("Errore: email vuota. Controllare il file utenti.txt\n");
        return 0; // Errore
    }
    if (nickname == NULL || nickname[0] == '\0') {
        printf("Errore: nickname vuoto. Controllare il file utenti.txt\n");
        return 0; // Errore
    }
    if (salt_hex == NULL || salt_hex[0] == '\0') {
        printf("Errore: salt_hex vuoto. Controllare il file utenti.txt\n");
        return 0; // Errore
    }
    if (hash_hex == NULL || hash_hex[0] == '\0') {
        printf("Errore: hash_hex vuoto. Controllare il file utenti.txt\n");
        return 0; // Errore
    }

    return 1; // Successo
}


//separa il body nei campi nickname e password
int login_split_body(const char *body, char *nickname, char *password) {
  if (!split_in_two(body, "::", nickname, password, small_size, small_size)) {
    printf("Errore nello split di email e password.\n");
    return 0;
  }
  
  // Controlla che nickname e password non siano vuoti
  if (nickname == NULL || nickname[0] == '\0') {
      printf("Errore: nickname vuoto.\n");
      return 0; // Errore
  }
  if (password == NULL || password[0] == '\0') {
      printf("Errore: password vuota.\n");
      return 0; // Errore
  }
  return 1; //Successo
}

//separa il body nei campi titolo e testo
int add_split_body(const char *body, char *autore, char *titolo, char *testo){

  char var_temporanea[post_testo_size + large_size];
  
  if (!split_in_two(body, "::", autore, var_temporanea, small_size, post_testo_size + large_size)) {
    printf("Errore nello split di autore\n");
    return 0;
  }
  
  if (!split_in_two(var_temporanea, "::", titolo, testo, large_size, post_testo_size)) {
    printf("Errore nello split di titolo e testo.\n");
    return 0;
  }
  
  // Controlla che autore, titolo e testo non siano vuoti
  if (autore == NULL || autore[0] == '\0') {
    printf("Errore: autore vuoto.\n");
    return 0; // Errore
  }
  if (titolo == NULL || titolo[0] == '\0') {
    printf("Errore: titolo vuoto.\n");
    return 0; // Errore
  }
  if (testo == NULL || testo[0] == '\0') {
    printf("Errore: testo vuoto.\n");
    return 0; // Errore
  }

  return 1; //Successo
}

#endif /* UTIL_H2 */
