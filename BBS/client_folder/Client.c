#include <stdatomic.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>


#include "../shared_folder/util.h"
#include "../shared_folder/aes.h"
#include "../shared_folder/rsa.h"

//#define DEBUG
#if !defined (TIMEOUT_SEC)
#define TIMEOUT_SEC 600 // Timeout di inattività in secondi
#endif

const char* file_public_key ="shared_folder/public_key.pem"; //file con chiave pubblica RSA

// Variabili globali per monitorare lo stato dei thread
atomic_int threadReceive_active = 1; // Flag per il thread Receive
atomic_int threadSend_active = 1; // Flag per il thread Send
atomic_int terminate_threadReceive = 0; // Segnale di terminazione per il thread Receive
atomic_int terminate_threadSend = 0; // Segnale di terminazione per il thread Send

// Variabile globale atomica per il nickname
_Atomic(char *) shared_string_nickname = NULL;

// Scrittura atomica per il nickname
void atomic_write_nickname(const char *new_value) {
    char *new_string = strdup(new_value); // Crea una nuova copia della stringa
    char *old_string = atomic_exchange(&shared_string_nickname, new_string); // Scambia in modo atomico
    free(old_string); // Libera la vecchia stringa
}

// Lettura atomica per il nickname
char *atomic_read_nickname() {
    return atomic_load(&shared_string_nickname); // Carica in modo atomico
}

// Struttura dati per passare informazioni ai thread
typedef struct {
    int sock;
    unsigned char *aes_key;
    unsigned char *iv;
    atomic_int *loggedin;
} thread_args;

//print del messaggio principale
void print_messaggio(int loggedin){
  if(loggedin == 0)
        printf("Digita 'register' per registrarti, 'login' per accedere o 'close' per chiudere il programma\nIl doppio carattere '::' non verrà accettato\n");
  else
    printf("Digita 'add' per aggiungere un post, 'list' per leggere un post, 'logout' per uscire o 'close' per chiudere il programma\n");
}

// Funzione per definire la registrazione
int registrazione(char *stringa) {
  if (stringa == NULL)
    return 0;
  printf("Registrazione in corso...\n");
  int i = 0;

  char *email = malloc(small_size * sizeof(char));
  char *nickname = malloc(small_size * sizeof(char));
  char *password = malloc(small_size * sizeof(char));
  if (email == NULL || nickname == NULL || password == NULL) {
    perror("Errore sulla malloc\n");
    exit(EXIT_FAILURE);
  }

  do {
    printf("Inserisci la tua email: ");
    i = myscanf(email, 4, small_size - 1);
  } while (i <= 0);

  do {
    printf("Inserisci il tuo nickname: ");
    i = myscanf(nickname, 4, small_size - 1);
  } while (i <= 0);

  do {
    printf("Inserisci la password: ");
    i = myscanf(password, 4, small_size - 1);
  } while (i <= 0);

  #ifdef DEBUG
  printf("Sono stati inseriti i seguenti dati:\n");
  printf("email: %s\n", email);
  printf("nickname: %s\n", nickname);
  printf("password: %s\n", password);
  #endif

  char *stringa1 = malloc(large_size * sizeof(char));
  if (stringa1 == NULL) {
    perror("Errore sulla malloc\n");
    exit(EXIT_FAILURE);
  }
  myconcat(stringa1, large_size, email, "::", nickname);
  myconcat(stringa, large_size, stringa1, "::", password);
  #ifdef DEBUG
  printf("stringa: %s\n", stringa);
  #endif
  myfree(&stringa1);
  myfree(&email);
  myfree(&nickname);
  myfree(&password);
  return strlen(stringa);
}

//funzione per definire 'add'
int write_post(char *stringa, int dim_max_post){
  if (stringa == NULL)
    return 0;
  printf("Scrittura post:\n");
  if((dim_max_post > post_testo_size) && (post_testo_size > very_large_size + large_size)){
    char *titolo = malloc(large_size * sizeof(char));
    int body_dim = dim_max_post - very_large_size;
    char *body = malloc(body_dim * sizeof(char));
    if (titolo == NULL || body == NULL) {
        perror("Errore sulla malloc\n");
        exit(EXIT_FAILURE);
    }
    
    int i = 0;
    do {
      printf("Inserisci il titolo del post: ");
      i = myscanf(titolo, 1, large_size - 1);
    } while (i <= 0);
    do {
      printf("Inserisci il testo del post: ");
      i = myscanf(body, 1, body_dim - 1);
    } while (i <= 0);
    
   
    char x = 'n';
    printf("Sei sicuro di voler aggiungere questo post? [Y] or [n]: ");
    if (scanf(" %c", &x) == 1) { 
      if( x == 'Y'){
        clear_input_buffer();
        char *stringa1 = malloc(dim_max_post * sizeof(char));
        if (stringa1 == NULL) {
          perror("Errore sulla malloc\n");
          exit(EXIT_FAILURE);
        }   
        myconcat(stringa1, very_large_size, titolo, "::", body);
        myconcat(stringa, dim_max_post, atomic_read_nickname(), "::", stringa1);
        myfree(&stringa1);
        #ifdef DEBUG
        printf("stringa: %s\n", stringa);
        #endif
        myfree(&titolo);
        myfree(&body);
        return strlen(stringa);
      }
    }
    clear_input_buffer();
    myfree(&titolo);
    myfree(&body);
  } else
    printf("Errore interno durante la scrittura del post, contattare l'assistenza\n");
  return 0;
}

// Funzione per definire il login
int login(char *stringa) {
    if (stringa == NULL)
      return 0;
    printf("Login in corso...\n");

    int i = 0;
    char *nickname = malloc(small_size * sizeof(char));
    char *password = malloc(small_size * sizeof(char));
    if (nickname == NULL || password == NULL) {
        perror("Errore sulla malloc\n");
        return 0;
    }

    do {
        printf("Inserisci il tuo nickname: ");
        i = myscanf(nickname, 4, small_size - 1);
    } while (i <= 0);

    do {
        printf("Inserisci la password: ");
        i = myscanf(password, 4, small_size - 1);
    } while (i <= 0);

    myconcat(stringa, large_size, nickname, "::", password);
    atomic_write_nickname(nickname);
    myfree(&nickname);
    myfree(&password);
    return strlen(stringa);
}

//funzione per definire il list
int flist(char *stringa){
  if (stringa == NULL)
    return 0;
  int i = 0;
  int inserimento_corretto= 0;
  do {
    i = 0;
    printf("Quanti messaggi vuoi caricare? (tra 1 e 999): ");
    i = myscanf(stringa, 1, 3);
    if(i >3 || !IsNumber(stringa)){
      printf("Non hai inserito un valore nell'intervallo valido\n");
    clear_buffer(stringa, small_size);
  }
  else
    inserimento_corretto = 1;
  } while (!inserimento_corretto);
  return (strlen(stringa));
}


// Funzione per definire fget
int fget(char *stringa) {
    if (stringa == NULL)
        return 0;

    int i = 0;
    do {
        printf("Inserisci l'ID del post da cercare: ");
        i = myscanf(stringa, 4, 4);
    } while (i <= 0);

    return strlen(stringa);
}

// Funzione per gestire la ricezione dei messaggi
void* receive_thread(void* arg) {
  thread_args* args = (thread_args*) arg;
  int sock = args->sock;
  unsigned char *aes_key = args->aes_key;
  unsigned char *iv = args->iv;
  atomic_int *loggedin = args->loggedin;
  unsigned char buffer[BUFFER_SIZE] = {0};
  
  while(!terminate_threadReceive){
    if(!threadSend_active){
      #ifdef DEBUG
      printf("Thread Send terminato. Thread Receive si autodistrugge.\n");
      #endif
      terminate_threadReceive = 1;
      break;
    }       
    
    clear_buffer(buffer, BUFFER_SIZE);
    int valread = read(sock, buffer, BUFFER_SIZE);
    if (valread == 0) {
      //printf("Connessione chiusa dal server\n");
      printf("Connessione chiusa\n");
      terminate_threadReceive = 1;
      } else if (valread > 0) {
        unsigned char *decrypted_msg = (unsigned char *)malloc(valread + 1);
        if (decrypted_msg == NULL) {
          perror("Errore sulla malloc per il messaggio decifrato\n");
        } else {
          int decrypted_len = decrypt(buffer, valread, aes_key, iv, decrypted_msg);
          if (decrypted_len > 0) {
            decrypted_msg[decrypted_len] = '\0';
            #ifdef DEBUG
            printf("Ricevuto: %s\n", decrypted_msg);
            #endif
            //caso di login
            if(strcmp((char*)decrypted_msg, "LOGIN_OK")==0 && *loggedin == 0){
              *loggedin = 1;
              printf("Login eseguito, utente: %s\n", atomic_read_nickname());
              print_messaggio(*loggedin);
            } else {
              //casi list o get: devo splittare i campi del post
              if (strncmp((char*)decrypted_msg, "LIST::", 6)==0 || strncmp((char*)decrypted_msg, "GET::", 5)==0 ){
                char id_post[small_size]= {0};
                char autore_post[small_size]= {0};
                char titolo_post[large_size] = {0};
                char testo_post[post_testo_size] = {0};
                if (post_split_body((char*)decrypted_msg, id_post, autore_post, titolo_post, testo_post) == 1){
                  printf("\nPost ID: %s\nautore: %s\ntitolo: %s\ntesto: %s\n\n", id_post, autore_post, titolo_post, testo_post);
                }
                else 
                  printf("Errore nella lettura del messaggio\n");
                clear_buffer(buffer, BUFFER_SIZE);
              }
              else
                printf("%s\n", decrypted_msg);
            }
          } else {
            printf("Errore nella decifratura del messaggio\n");
          }
          free(decrypted_msg);
        }
      }
    }
  threadReceive_active = 0;
  #ifdef DEBUG
  printf("terminazione thread receive\n");
  #endif
  pthread_exit(NULL);  // Termina il thread
  //return NULL;
}

// Funzione per gestire l'invio dei messaggi
void* send_thread(void* arg) {
    thread_args* args = (thread_args*) arg;
    int sock = args->sock;
    unsigned char *aes_key = args->aes_key;
    unsigned char *iv = args->iv;
    
  // Carica la chiave pubblica RSA
    EVP_PKEY *pub_key = load_public_RSA_key(file_public_key);
    if (!pub_key) {
        fprintf(stderr, "Errore nel caricamento della chiave pubblica RSA\n");
        terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
    }

    // Cifra la chiave AES con RSA
    unsigned char encrypted_key[RSA_KEY_SIZE];
    int encrypted_key_len = encrypt_RSA(pub_key, aes_key, AES_KEY_SIZE, encrypted_key);
    if (encrypted_key_len <= 0) {
        fprintf(stderr, "Errore nella cifratura della chiave AES\n");
        EVP_PKEY_free(pub_key);
        terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
    }

    EVP_PKEY_free(pub_key);

    // Invia la lunghezza della chiave cifrata
    if (send(sock, &encrypted_key_len, sizeof(encrypted_key_len), 0) <= 0) {
        perror("Errore nell'invio della lunghezza della chiave cifrata\n");
        terminate_threadSend = 1;
    }

    // Invia la chiave AES cifrata al server
    if (send(sock, encrypted_key, encrypted_key_len, 0) <= 0) {
        perror("Errore nell'invio della chiave AES cifrata\n");
        terminate_threadSend = 1;
    }

    // Invia l'IV non cifrato al server
    if (send(sock, iv, AES_BLOCK_SIZE, 0) <= 0) {
      perror("Errore nell'invio dell'IV\n");
      terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
    }

    #ifdef DEBUG
    printf("key: ");
    myprintbytes(aes_key, AES_KEY_SIZE);  
    printf("IV : ");
    myprintbytes(iv, AES_BLOCK_SIZE);  
    printf("chiave cifrata: ");
    myprintbytes(encrypted_key, AES_KEY_SIZE);
    printf("Chiave AES e IV inviati al server.\n");
    #endif

    char *msg = malloc(BUFFER_SIZE * sizeof(char));
    if (msg == NULL) {
        perror("Errore sulla malloc\n");
        terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
    }

    print_messaggio(0);
    
    fd_set readfds;
    struct timeval timeout;
    int activity;
    atomic_int *loggedin = args->loggedin; //booleano che indica se l'utente è loggato oppure no
    
    while (!terminate_threadSend) {
      //print_messaggio(*loggedin);
      FD_ZERO(&readfds);
      FD_SET(STDIN_FILENO, &readfds);
      FD_SET(sock, &readfds);

      timeout.tv_sec = TIMEOUT_SEC;
      timeout.tv_usec = 0;

      activity = select(sock + 1, &readfds, NULL, NULL, &timeout);
      if(!threadReceive_active){
        #ifdef DEBUG
        printf("Thread Receive terminato. Thread Send si autodistrugge.\n");
        #endif
        terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
        break;
      }

      if (activity < 0) {
        perror("Errore nella select\n");
        terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
        break;
      } else if (activity == 0) {
        printf("Timeout di inattività raggiunto. Disconnessione...\n");
        terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
        break;
      }

      if (FD_ISSET(STDIN_FILENO, &readfds)) {
        int c = myscanf(msg, 0, BUFFER_SIZE - 1);
        (void)c; // Disattiva il warning di "unused variable"
        if (strcmp(msg, "close") == 0 || strcmp(msg, "Close") == 0 || strcmp(msg, "CLOSE") == 0) {
          terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
        } else {
            //print_messaggio(*loggedin);
            if (strcmp(msg, "register") == 0 || strcmp(msg, "register ") == 0 || strcmp(msg, "Register") == 0 || strcmp(msg, "REGISTER") == 0) {
              if(*loggedin == 0){
                char *reg=malloc(large_size * sizeof(char));
                if (reg == NULL) {
                  perror("Errore sulla malloc\n");
                  terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
                } else {
                  registrazione(reg);
                  char *reg2=malloc(sizeof(char) *very_large_size);
                  if(reg2 == NULL){
                    perror("Errore sulla malloc\n");
                    terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
                  } else {
                    myconcat(reg2, very_large_size, "register", "::", reg);
                    myfree(&reg);
                    send_encrypted_message(sock, aes_key, iv, reg2);
                    free(reg2);
                    //invio la sfida (numero di 6 cifre) al server
                    char n_sfida[7];
                    int i = 0;
                    int inserimento_corretto= 0;
                    do {
                      i = 0;
                      printf("Inserisci il valore della sfida: ");
                      i = myscanf(n_sfida, 6, 6);
                      if(i!= 6 || !IsNumber(n_sfida)){
                        printf("Non hai inserito un valore valido per la sfida\n");
                        clear_buffer(n_sfida, 7);
                      }
                      else
                        inserimento_corretto = 1;
                    } while (!inserimento_corretto);
                    send_encrypted_message(sock, aes_key, iv, n_sfida);
                  }
                }
              } else
                printf("Non puoi effettuare una registrazione mentre sei loggato\n");
          } else if (strcmp(msg, "login") == 0 || strcmp(msg, "login ") == 0 || strcmp(msg, "Login") == 0 || strcmp(msg, "LOGIN") == 0) {
            if(*loggedin == 0){
              char *log=malloc(large_size * sizeof(char));
              if (log == NULL) {
                perror("Errore sulla malloc\n");
                terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
              } else {
                login(log);
                char *log2= malloc(sizeof(char) * very_large_size);
                if(log2 == NULL){
                  perror("Errore sulla malloc\n");
                  terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
                } else {
                  myconcat(log2, very_large_size, "login", "::", log);
                  myfree(&log);
                  send_encrypted_message(sock, aes_key, iv, log2);
                  free(log2);
                }
              }
            } else
              printf("Non puoi effettuare il login mentre sei loggato, fai prima un logout\n");
          } else if(strcmp(msg, "logout") == 0 || strcmp(msg, "Logout") == 0 || strcmp(msg, "LOGOUT") == 0){
            if (*loggedin == 1){
              *loggedin = 0;
              send_encrypted_message(sock, aes_key, iv, "logout");
              printf("Logout eseguito\n");
              print_messaggio(*loggedin);
            } else
              printf("Comando 'logout' non eseguito, perchè non sei loggato\n");
          }
          else if(strcmp(msg, "add") == 0 || strcmp(msg, "add ") == 0 || strcmp(msg, "Add") == 0 || strcmp(msg, "ADD") == 0){
            if(*loggedin == 1){
              #ifdef DEBUG
              printf("Comando 'add' riconosciuto...\n");
              #endif
              int dim_max_post = BUFFER_SIZE - 5;
              char *post=malloc(dim_max_post * sizeof(char));
              if (post == NULL) {
                perror("Errore sulla malloc\n");
                terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
              } else {
                if (write_post(post, dim_max_post) > 0){
                  char *post2= malloc(sizeof(char) * BUFFER_SIZE);
                  if(post2 == NULL){
                    perror("Errore sulla malloc\n");
                    terminate_threadSend = 1; // Invia segnale di terminazione a sé stesso
                  } else {
                    myconcat(post2, BUFFER_SIZE, "add", "::", post);
                    send_encrypted_message(sock, aes_key, iv, post2);
                    free(post2);
                  }
                }
                myfree(&post);
              }
            }
            else
              printf("Comando 'add' non eseguito, perchè non sei loggato\n");
          }
          else
            if(strcmp(msg, "list") == 0 || strcmp(msg, "list ") == 0 || strcmp(msg, "List") == 0 || strcmp(msg, "LIST") == 0){
              if(*loggedin == 1){
                #ifdef DEBUG
                printf("Comando 'list' riconosciuto...\n");
                #endif
                char n[small_size] = {0};
                if (flist(n) > 0){
                  char lis[medium_size] = {0};
                  myconcat(lis, medium_size, "list", "::", n);
                  send_encrypted_message(sock, aes_key, iv, lis);
                }
                else
                  printf("Comando 'list' non eseguito, perchè non hai inserito un valore corretto\n");
                
              }
              else
                printf("Comando 'list' non eseguito, perchè non sei loggato\n");
            }
            else
              if(strcmp(msg, "get") == 0 || strcmp(msg, "get ") == 0 || strcmp(msg, "Get") == 0 || strcmp(msg, "GET") == 0){
                if(*loggedin == 1){
                  #ifdef DEBUG
                  printf("Comando 'get' riconosciuto...\n");
                  #endif
                  char id[small_size] = {0};
                  if (fget(id) == 4){
                    char ge[medium_size] = {0};
                    myconcat(ge, medium_size, "get", "::", id);
                    send_encrypted_message(sock, aes_key, iv, ge);
                  }
                  else
                    printf("Comando 'get' non eseguito, perchè non hai inserito un valore corretto\n");
                }
                else
                  printf("Comando 'get' non eseguito, perchè non sei loggato\n");
              }
              else{
                #ifdef DEBUG
                printf("Comando ricevuto: '%s'\n", msg);
                //comando segreto per testare il comportamento del programma in caso di messaggi forgiati
                //Naturalmente nel programma vero questa opzione non va inclusa
                if(strcmp(msg, "hack") == 0 ){
                  printf("Hack this program! Digit every message you want!:\n");
                  char *hack = malloc(sizeof(char)*BUFFER_SIZE);
                  scanf("%[^\n]s",hack);
                  send_encrypted_message(sock, aes_key, iv, hack);
                  free(hack);
                }
                else
                #endif
                printf("Comando non riconosciuto\n");
              }
        }
      }
    }
  threadSend_active = 0;
  if(msg)
    myfree(&msg);
  #ifdef DEBUG
  printf("terminazione thread send\n");
  #endif
  shutdown(sock, SHUT_RD); // Chiudi la parte di lettura della socket
  pthread_exit(NULL);  // Termina il thread
  //return NULL;
}

// Funzione per gestire la comunicazione con il server
void handle_communication(int sock, unsigned char *key, unsigned char *iv) {

    atomic_int loggedin = 0; //se l'utente è loggato
    // Crea i thread per invio e ricezione
    pthread_t send_tid, receive_tid;
    thread_args args = {sock, key, iv, &loggedin};

    if (pthread_create(&receive_tid, NULL, receive_thread, &args) != 0) {
        perror("Errore nella creazione del thread di ricezione\n");
        terminate_threadSend = 1; 
    }
    else{
      if (pthread_create(&send_tid, NULL, send_thread, &args) != 0) {
        perror("Errore nella creazione del thread di invio\n");
        terminate_threadReceive = 1;
      }
      else
        //Attendi la terminazione del thread send
        pthread_join(send_tid, NULL);       
      // Attendi la terminazione del thread receive
      pthread_join(receive_tid, NULL);
    }
}

int main(int argc, char *argv[]) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    atomic_write_nickname("\0");

    printf("Client\n");

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error\n");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address\n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed\n");
        return -1;
    }

    unsigned char key[AES_KEY_SIZE], iv[AES_BLOCK_SIZE];
    if (!generate_aes_key(key, iv)) {
        return 1;
    }
    handle_communication(sock, key, iv);
    free(atomic_read_nickname());
    close(sock);

    return 0;
}
