#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <pthread.h>

#define ID_LENGTH 4
#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define CHARSET_SIZE 62
#define COUNTER_FILE "server_folder/counter.txt"
#define TEMP_FILE "server_folder/counter.tmp"
#define MAX_IDS 14776336 // 62^4, numero massimo di id che è possibile generare

pthread_mutex_t genera_id_lock = PTHREAD_MUTEX_INITIALIZER;  // Mutex per garantire la sincronizzazione

// Funzione per convertire un numero intero in una stringa alfanumerica
void int_to_alphanum(int num, char *id) {
    for (int i = ID_LENGTH - 1; i >= 0; i--) {
        id[i] = CHARSET[num % CHARSET_SIZE];
        num /= CHARSET_SIZE;
    }
    id[ID_LENGTH] = '\0'; // Terminatore di stringa
}

// Funzione per leggere e incrementare il contatore nel file
// Ritorna 0 per successo, -1 per fallimento
int generate_id_from_file(char *id) {
    int counter;
    int fd = open(COUNTER_FILE, O_RDWR | O_CREAT, 0666); // Apri il file in modalità lettura/scrittura

    if (fd == -1) {
        perror("Errore nell'apertura del file\n");
        return -1;
    }

    // Blocca il file per evitare accessi concorrenti
    if (flock(fd, LOCK_EX) == -1) {
        perror("Errore nel lock del file\n");
        close(fd);
        return -1;
    }

    // Leggi il contatore dal file (se il file è vuoto, inizia da 0)
    if (read(fd, &counter, sizeof(counter)) != sizeof(counter)) {
        counter = 0; // File vuoto o errore di lettura
    #ifdef DEBUG
        printf("Contatore inizializzato a 0\n");
    } else {
        printf("Contatore letto: %d\n", counter);
    #endif
    }

    // Verifica se il contatore ha superato il massimo numero di ID
    if (counter >= MAX_IDS) {
        fprintf(stderr, "Errore: raggiunto il massimo numero di ID disponibili\n");
        flock(fd, LOCK_UN); // Rilascia il lock
        close(fd);
        return -1; // Fallimento
    }

    // Genera l'ID alfanumerico
    int_to_alphanum(counter, id);

    // Incrementa il contatore
    counter++;

    // Usa un file temporaneo per salvare il nuovo contatore
    int temp_fd = open(TEMP_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (temp_fd == -1) {
        perror("Errore nell'apertura del file temporaneo\n");
        flock(fd, LOCK_UN); // Rilascia il lock
        close(fd);
        return -1;
    }

    // Scrivi il contatore nel file temporaneo
    if (write(temp_fd, &counter, sizeof(counter)) != sizeof(counter)) {
        perror("Errore nella scrittura del file temporaneo\n");
        close(temp_fd);
        flock(fd, LOCK_UN); // Rilascia il lock
        close(fd);
        return -1;
    }

    close(temp_fd); // Chiudi il file temporaneo

    // Sostituisci il file originale con il file temporaneo
    if (rename(TEMP_FILE, COUNTER_FILE) == -1) {
        perror("Errore nel rinominare il file temporaneo\n");
        remove(TEMP_FILE); // Rimuovi il file temporaneo se l'operazione fallisce
        flock(fd, LOCK_UN); // Rilascia il lock
        close(fd);
        return -1;
    }

    // Rilascia il lock sul file
    if (flock(fd, LOCK_UN) == -1) {
        perror("Errore nel rilascio del lock\n");
        close(fd);
        return -1;
    }

    close(fd); // Chiudi il file originale
    return 1; // Successo
}

// Funzione che invoco per generare l'id
int genera_id(char *id, int id_len) {
  if(id_len == ID_LENGTH +1){
    pthread_mutex_lock(&genera_id_lock); // Acquisisce il mutex prima di generare l'ID
    if (generate_id_from_file(id) == 1) { // Genera l'ID leggendo dal file
      #ifdef DEBUG
      printf("ID generato: %s\n", id);
      #endif
    } else {
      fprintf(stderr, "Errore nella generazione dell'ID\n");
    }
    pthread_mutex_unlock(&genera_id_lock); // Rilascia il mutex dopo che l'ID è stato generato
    return 1; //Successo
  }
  return 0; //Fallimento
}

