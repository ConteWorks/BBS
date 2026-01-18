#if !defined(UTIL_H)
#define UTIL_H

#if !defined(BUFFER_SIZE)
#define BUFFER_SIZE 4048
#endif

#if !defined(PORT)
#define PORT 8080
#endif

#if !defined(IP)
#define IP "127.0.0.1"
#endif

#if !defined(small_size)
#define small_size 30
#endif

#if !defined(medium_size)
#define medium_size (small_size * 2 + 3)
#endif

#if !defined(large_size)
#define large_size (medium_size * 2 + 3)
#endif

#if !defined(very_large_size)
#define very_large_size (large_size + 12) //il +12 è lo spazio avanti di register:: 
#endif

#if !defined(post_testo_size)                                //il -12 è per conservare un po' di spazio ad add::
#define post_testo_size (BUFFER_SIZE - very_large_size - 12) //e all'id del post che verrà aggiunto al lato server,
#endif                                                       //in modo da non dover calcolare ogni volta la dimensione precisa del buffer del socket

#if !defined(RSA_KEY_SIZE)
#define RSA_KEY_SIZE 256 // Per una chiave RSA a 2048 bit
#endif

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h> // Per isdigit
#include <unistd.h>
#include <math.h>

#include "aes.h"


void clear_buffer(void *buffer, size_t size){
    memset(buffer, '\0', size);
}

// Funzione per svuotare il buffer di input in caso di overflow
void clear_input_buffer() {
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF);
}

// Funzione per leggere una stringa di almeno 'minsize' e al massimo 'maxsize' caratteri, ed evitare il simbolo ::
int myscanf(char *str, int minsize, int maxsize) {
    int i = 0;
    int ch;

    // Inizializza il buffer della stringa
    memset(str, 0, maxsize + 1);
    while (1) {
        ch = getchar(); // Leggi un carattere

        // Fine dell'input: riga completata o EOF
        if (ch == '\n' || ch == EOF) {
            // Controlla se la lunghezza è inferiore al minimo richiesto
            if (i < minsize) {
                if (minsize == maxsize)
                    printf("Il testo è troppo corto, il testo deve avere esattamente %d caratteri\n", minsize);
                else
                    printf("Il testo è troppo corto, il testo deve avere almeno %d caratteri\n", minsize);

                str[0] = '\0';        // Resetta la stringa
                return -1;            // Indica un errore
            } else {
                break; // La stringa è valida
            }
        }

        // Controllo per evitare doppio ':'
        if (i > 0 && str[i - 1] == ':' && ch == ':') {
            continue; // Ignora il secondo ':'
        }

        // Controlla se si è raggiunta la lunghezza massima consentita
        if (i >= maxsize) { // Considera maxsize caratteri più terminatore nullo
            if (minsize == maxsize)
                printf("Il testo è troppo lungo, il testo deve avere esattamente %d caratteri\n", maxsize);
            else
                printf("Il testo è troppo lungo, il testo può avere al massimo %d caratteri\n", maxsize);

            clear_input_buffer(); // Svuota l'input rimanente
            str[0] = '\0';        // Resetta la stringa
            return -1;            // Indica un errore
        }

        // Aggiunge il carattere al buffer
        str[i++] = ch;
    }

    // Aggiungi il terminatore nullo alla fine della stringa
    str[i] = '\0';
    return i; // Ritorna la lunghezza effettiva della stringa
}

void myfree(char **x) {
  if (*x != NULL) {
    free(*x);
    *x = NULL;
  }
}

// Funzione per convertire una stringa in un array di unsigned char (byte)
void convertStrToByte(unsigned char *buffer, const char *str, size_t buffer_size) {
    size_t len = strnlen(str, buffer_size - 1); // Usa strnlen per limitare la lunghezza
    memcpy(buffer, str, len);
    buffer[len] = '\0'; // Aggiunge il terminatore nullo
}

// Funzione per convertire un array di byte (unsigned char) in una stringa
void convertByteToStr(char *buffer, const unsigned char *str, size_t buffer_size) {
    size_t len = strnlen((const char *)str, buffer_size - 1);
    memcpy(buffer, str, len);
    buffer[len] = '\0';
}

void myprintbytes2(const unsigned char *s){
    size_t len = strlen((const char *)s);
    for(int i = 0; i < len; i++){
        printf("%02x ", s[i]);
    }
    printf("\n");
}

void myByteCopy(unsigned char *buffer, const unsigned char *data, size_t data_size){
    if (buffer == NULL || data == NULL) {
        // Gestione dell'errore: buffer o data non validi
        return;
    }

    // Copia i dati binari
    memcpy(buffer, data, data_size);
}

void myprintbytes(const unsigned char *data, size_t data_size){
    for (size_t i = 0; i < data_size; i++){
        printf("%02x ", data[i]);
    }
    printf("\n");
}

void myprint(const unsigned char *data, size_t data_size){
    for (size_t i = 0; i < data_size; i++){
        printf("%c", data[i]);
    }
    printf("\n");
}

//concatena le stringhe "s1 separator s2" e salva la stringa risultante in destination
static inline void myconcat(char *destination, size_t dest_size, const char *s1, const char *separator, const char *s2){
    snprintf(destination, dest_size, "%s%s%s", s1, separator, s2);
    
    // Garantire che la stringa sia terminata correttamente
    destination[dest_size - 1] = '\0';
}

// Calcola la lunghezza di una stringa
int string_length(const char *str) {
    int length = 0;
    while (str[length] != '\0') { // Itera finché non trova il terminatore di stringa
        length++;
    }
    return length;
}

/// Funzione per dividere in due parti la stringa
int split_in_two(const char *stringa, const char *separatore, char *prima_parte, char *seconda_parte, int prima_parte_len, int seconda_parte_len) {
    // Trova la prima occorrenza della sequenza di separatori nella stringa
    const char *posizione_separatore = strstr(stringa, separatore);

    // Se il separatore non è trovato, copia tutta la stringa in prima_parte se c'è spazio
    if (posizione_separatore == NULL) {
        if (string_length(stringa) >= prima_parte_len) {
            return 0; // Fallimento: stringa troppo lunga per il buffer prima_parte
        }
        strcpy(prima_parte, stringa); // Copia tutta la stringa nella prima parte
        seconda_parte[0] = '\0';      // Imposta seconda_parte come stringa vuota
        return 1; 
    }

    // Calcola la lunghezza della prima parte
    int lunghezza_prima_parte = posizione_separatore - stringa;

    // Verifica che la prima parte non ecceda la lunghezza massima
    if (lunghezza_prima_parte >= prima_parte_len) {
        return 0; // Fallimento: prima_parte troppo lunga per il buffer
    }

    // Copia la prima parte della stringa fino al separatore
    strncpy(prima_parte, stringa, lunghezza_prima_parte);
    prima_parte[lunghezza_prima_parte] = '\0'; // Terminatore per la prima stringa

    // Copia la seconda parte dopo il separatore (usando la lunghezza del separatore)
    const char *start_seconda_parte = posizione_separatore + strlen(separatore);

    // Verifica che la seconda parte non ecceda la lunghezza massima
    if (string_length(start_seconda_parte) >= seconda_parte_len) {
        return 0; // Fallimento: seconda_parte troppo lunga per il buffer
    }

    strcpy(seconda_parte, start_seconda_parte);

    return 1; // Ritorna 1 per indicare che la separazione ha avuto successo
}

//funzione che genera un numero casuale di 6 cifre
int generate_random_6_digit_number() {
    // Imposta il seme per la generazione di numeri casuali basandosi sull'orologio
    srand(time(NULL)); 

    // Genera un numero casuale tra 100000 e 999999
    return 100000 + rand() % 900000;
}

// Funzione che verifica se la stringa contiene solo caratteri numerici
int IsNumber(const char *str) {
    // Verifica se la stringa è NULL o vuota
    if (str == NULL || *str == '\0') {
        return 0; // False: non è un numero
    }

    // Scorri ogni carattere della stringa
    for (int i = 0; str[i] != '\0'; i++) {
        if (!isdigit((unsigned char)str[i])) {
            return 0; // False: non è un numero
        }
    }

    return 1; // True: tutti i caratteri sono cifre
}

//conta di quante cifre è composto l'intero num
int count_digits(int num) {
    // Rendi il numero positivo se è negativo
    if (num < 0) {
        num = -num;
    }

    int count = 0;

    // Gestisci il caso speciale per 0
    if (num == 0) {
        return 1;
    }

    // Conta le cifre dividendo per 10
    while (num > 0) {
        count++;
        num /= 10;
    }

    return count;
}

// Funzione per inviare dati cifrati
void send_encrypted_message(int sock, unsigned char *key, unsigned char *iv, char *msg) {
    #ifdef DEBUG
    printf("Sarà inviata la seguente frase: %s\n", msg);
    unsigned char sent[BUFFER_SIZE];
    #endif
    unsigned char buffer[BUFFER_SIZE];
    clear_buffer(buffer, BUFFER_SIZE);
    int c = encrypt((unsigned char *)msg, strlen(msg), key, iv, (unsigned char *)buffer);
    #ifdef DEBUG
    memcpy(sent, buffer, BUFFER_SIZE);
    #endif
    if (send(sock, buffer, c, 0) == -1) {
        perror("Errore nell'invio");
    } 
    #ifdef DEBUG
      else {
        printf("Message sent\n");
        printf("E' stato inviato il seguente messaggio criptato: ");
        myprintbytes2(sent);
        }
    #endif
}

//verifica se il canale socket è ancora attivo
int check_socket(int sockfd) {
    char buffer[1];
    ssize_t result = read(sockfd, buffer, sizeof(buffer));

    if (result == 0) {
        // La connessione è stata chiusa dal peer
        printf("Connection closed by peer\n");
        return 0; // Socket chiusa
    } else if (result == -1) {
        // Errore nella lettura, controlla l'errore
        if (errno == ECONNRESET) {
            // La connessione è stata resettata (il peer ha chiuso la connessione in modo forzato)
            printf("Connection reset by peer\n");
        } else {
            // Altri errori
            perror("Read error");
        }
        return -1; // Errore nella lettura
    } else {
        // La socket è ancora attiva, possiamo continuare a leggere/scrivere
        return 1;
    }
}

//separa il post nei campi id, autore, titolo e testo
int post_split_body(const char *body, char* id, char *autore, char *titolo, char *testo){

  // Inizializza i buffer come stringhe vuote
  id[0] = '\0';
  autore[0] = '\0';
  titolo[0] = '\0';
  testo[0] = '\0';
  
  char var_temporanea1[BUFFER_SIZE] = {0};
  char var_temporanea2[BUFFER_SIZE] = {0};
  char var_temporanea3[BUFFER_SIZE] = {0};
  char l[small_size] = {0};
  
  //tolgo "LIST:: o GET::"
  if (!split_in_two(body, "::", l, var_temporanea1, small_size, BUFFER_SIZE)) {
    printf("Errore nello split del post\n");
    return 0;
  }
  
  //estraggo l'id
  if (!split_in_two(var_temporanea1, "::", id, var_temporanea2, small_size, BUFFER_SIZE)) {
    printf("Errore nello split di id\n");
    return 0;
  }
  
  //estraggo l'autore
  if (!split_in_two(var_temporanea2, "::", autore, var_temporanea3, small_size, BUFFER_SIZE)) {
    printf("Errore nello split di autore\n");
    return 0;
  }
  
  //estraggo titolo e testo
  if (!split_in_two(var_temporanea3, "::", titolo, testo, large_size, post_testo_size)) {
    printf("Errore nello split di titolo e testo.\n");
    return 0;
  }
  return 1; //Successo
}

#endif /* UTIL_H */

