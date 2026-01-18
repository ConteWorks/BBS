#if !defined(FILE_UTIL_H)
#define FILE_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>

pthread_mutex_t file_posts_lock = PTHREAD_MUTEX_INITIALIZER;  // Mutex per garantire la sincronizzazione del file post
pthread_mutex_t file_users_lock = PTHREAD_MUTEX_INITIALIZER;  // Mutex per garantire la sincronizzazione del file utenti

/* Funzione per aggiungere una stringa alla fine del file in modo thread-safe */
int append_string_to_file(const char* filename, const char* string) {
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1) {
        perror("Errore nell'apertura del file");
        return 0;
    }

    if (flock(fd, LOCK_EX) == -1) {
        perror("Errore nel lock del file");
        close(fd);
        return 0;
    }

    FILE* file = fdopen(fd, "a");
    if (file == NULL) {
        perror("Errore nella scrittura del file");
        flock(fd, LOCK_UN);
        close(fd);  // Close the fd before returning
        return 0;
    }

    fprintf(file, "%s\n", string);
    fflush(file);

    flock(fd, LOCK_UN);
    fclose(file);

    return 1;
}


/* Funzione per leggere le ultime X righe dal file */
char** load_last_entries_from_file(const char* filename, int num_lines, int* lines_read) {
    int fd = open(filename, O_RDONLY | O_CREAT, 0644);
    if (fd == -1) {
        perror("Errore nell'apertura del file");
        return NULL;
    }

    if (flock(fd, LOCK_SH) == -1) {
        perror("Errore nel lock del file");
        close(fd);
        return NULL;
    }

    FILE* file = fdopen(fd, "r");
    if (file == NULL) {
        perror("Errore nell'apertura del file");
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }

    char** last_lines = malloc(num_lines * sizeof(char*));
    for (int i = 0; i < num_lines; i++) {
        last_lines[i] = NULL;
    }
    *lines_read = 0;

    char* line = NULL;
    size_t len = 0;
    while (getline(&line, &len, file) != -1) {
        if (*lines_read < num_lines) {
            last_lines[*lines_read] = strdup(line);
            (*lines_read)++;
        } else {
            free(last_lines[0]);
            memmove(last_lines, last_lines + 1, (num_lines - 1) * sizeof(char*));
            last_lines[num_lines - 1] = strdup(line);
        }
    }
    free(line);

    // Rimuove il newline alla fine di ogni riga, se presente
    for (int i = 0; i < *lines_read; i++) {
        last_lines[i][strcspn(last_lines[i], "\n")] = '\0';
    }

    flock(fd, LOCK_UN);
    fclose(file);

    return last_lines;
}

/*Funzione per leggere tutte le righe da un file e restituirle come un array di stringhe*/
char** load_all_entries_from_file(const char* filename, int* lines_read) {
    int fd = open(filename, O_RDONLY | O_CREAT, 0644); 
    if (fd == -1) {
        perror("Errore nell'apertura del file");
        return NULL;
    }

    if (flock(fd, LOCK_SH) == -1) {
        perror("Errore nel lock del file");
        close(fd);
        return NULL;
    }

    FILE* file = fdopen(fd, "r");
    if (file == NULL) {
        perror("Errore nell'apertura del file");
        flock(fd, LOCK_UN);
        close(fd);
        return NULL;
    }

    size_t capacity = 10;
    char** all_lines = malloc(capacity * sizeof(char*));
    if (all_lines == NULL) {
        perror("Errore di allocazione");
        flock(fd, LOCK_UN);
        fclose(file);
        return NULL;
    }

    *lines_read = 0;
    char* line = NULL;
    size_t len = 0;

    while (getline(&line, &len, file) != -1) {
        if (*lines_read >= capacity) {
            capacity *= 2;
            char** temp = realloc(all_lines, capacity * sizeof(char*));
            if (temp == NULL) {
                perror("Errore di realloc");
                free(line);
                for (int i = 0; i < *lines_read; i++) {
                    free(all_lines[i]);
                }
                free(all_lines);
                flock(fd, LOCK_UN);
                fclose(file);
                return NULL;
            }
            all_lines = temp;
        }

        // Rimuove il carattere '\n' alla fine della linea, se presente
        size_t line_length = strlen(line);
        if (line_length > 0 && line[line_length - 1] == '\n') {
            line[line_length - 1] = '\0';
        }

        all_lines[*lines_read] = strdup(line);
        if (all_lines[*lines_read] == NULL) {
            perror("Errore durante la duplicazione della stringa");
            free(line);
            for (int i = 0; i < *lines_read; i++) {
                free(all_lines[i]);
            }
            free(all_lines);
            flock(fd, LOCK_UN);
            fclose(file);
            return NULL;
        }

        (*lines_read)++;
    }

    free(line);

    flock(fd, LOCK_UN);
    fclose(file);

    return all_lines;
}

// Funzione per cercare una riga del post basata su un ID, supponendo che il post inizi con <<id(4 caratteri)>>::
char* find_post_by_id(const char* filename, const char* id) {
    if (filename == NULL || id == NULL || strlen(id) != 4) {
        fprintf(stderr, "Errore: file o ID non validi.\n");
        return NULL;
    }

    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("Errore nell'apertura del file");
        return NULL;
    }

    // Acquisisce un lock condiviso sul file
    if (flock(fd, LOCK_SH) == -1) {
        perror("Errore nell'acquisizione del lock");
        close(fd);
        return NULL;
    }

    FILE* file = fdopen(fd, "r");
    if (file == NULL) {
        perror("Errore nell'apertura del file stream");
        flock(fd, LOCK_UN); // Rilascia il lock
        close(fd);
        return NULL;
    }

    char buffer[BUFFER_SIZE]; // Buffer per leggere le righe
    while (fgets(buffer, sizeof(buffer), file) != NULL) {
        // Confronta i primi 4 caratteri della riga con l'ID
        if (strncmp(buffer, id, 4) == 0) {
            flock(fd, LOCK_UN); // Rilascia il lock
            fclose(file);

            // Restituisce una copia della riga trovata
            char* result = strdup(buffer);
            if (result != NULL) {
                // Rimuove il newline dalla fine della riga, se presente
                result[strcspn(result, "\n")] = '\0';
            }
            return result;
        }
    }

    // Se l'ID non viene trovato, rilascia il lock e chiude il file
    flock(fd, LOCK_UN);
    fclose(file);
    return NULL;
}


#endif /* FILE_UTIL_H */
