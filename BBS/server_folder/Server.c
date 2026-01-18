#include <stdatomic.h> //per dichiarare variabili atomiche
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>  
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/socket.h> 
#include <sys/types.h>
#include <netinet/in.h> 
#include <pthread.h>
#include <arpa/inet.h> 

#include "../shared_folder/util.h"
#include "../shared_folder/rsa.h"
#include "../shared_folder/aes.h"
#include "hash.h"
#include "file_util.h"
#include "util2.h"
#include "generaid.h"

#if !defined(MAX_CLIENTS)
#define MAX_CLIENTS 100
#endif

//#define DEBUG

#define MALLOC(ptr, size)                      \
    do {                                       \
        (ptr) = malloc((size) * sizeof(*(ptr))); \
        if ((ptr) == NULL) {                   \
            perror("Errore sulla malloc");     \
            exit(EXIT_FAILURE);                \
        }                                      \
    } while (0)
    
atomic_int close_server = 0;


int server_fd = 0;

int client_sockets[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER; //mutex per l'array dei clients

pthread_t client_threads[MAX_CLIENTS]; // Array per tenere traccia dei thread dei client
int thread_count = 0;

const char* file_private_key = "server_folder/private_key.pem"; //file con chiave privata RSA
const char* file_utenti = "server_folder/utenti.txt";
const char* file_post = "server_folder/posts.txt";

void remove_client_socket(int client_socket) {

    pthread_mutex_lock(&client_mutex);
    for (int i = 0; i < client_count; i++) {
        if (client_sockets[i] == client_socket) {
            client_sockets[i] = client_sockets[--client_count];
            break;
        }
    }
    pthread_mutex_unlock(&client_mutex);
}

void notify_and_close_all_clients() {
    pthread_mutex_lock(&client_mutex);
    for (int i = 0; i < client_count; i++) {
        //send(client_sockets[i], "Server is shutting down", strlen("Server is shutting down"), 0);
        shutdown(client_sockets[i], SHUT_RDWR);
        close(client_sockets[i]);
    }
    client_count = 0;
    pthread_mutex_unlock(&client_mutex);
}

void *socketThread(void *arg) {
    unsigned char buffer[BUFFER_SIZE];
    int client_socket = *((int *)arg);
    clear_buffer(buffer, BUFFER_SIZE);
    
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
        
    // Lettura della chiave AES cifrata
    int valread = 0;
    // Lettura della lunghezza della chiave cifrata
    int encrypted_key_len;
    if (read(client_socket, &encrypted_key_len, sizeof(encrypted_key_len)) <= 0) {
        fprintf(stderr, "Errore nella lettura della lunghezza della chiave cifrata\n");
        close(client_socket);
        pthread_exit(NULL);
    }
    
    // Controlla che la lunghezza ricevuta sia valida
    if (encrypted_key_len > RSA_KEY_SIZE) {
        fprintf(stderr, "Errore: lunghezza della chiave cifrata troppo grande\n");
        close(client_socket);
        pthread_exit(NULL);
    }
    
    // Lettura della chiave cifrata
    valread = read(client_socket, buffer, encrypted_key_len);
    
    if(valread > 0 && atomic_load(&close_server) == 0) {
        EVP_PKEY *priv_key = load_private_RSA_key(file_private_key);
        #ifdef DEBUG
        printf("Chiave cifrata ricevuta: ");
        myprintbytes(buffer, AES_KEY_SIZE);  // Stampa i dati binari correttamente
        #endif
        //decifra la chiave
        int decrypted_len = decrypt_RSA(priv_key, buffer, encrypted_key_len, key);
        if (decrypted_len == -1) {
            fprintf(stderr, "Errore nella decifratura\n");
            EVP_PKEY_free(priv_key);
            close(client_socket);
            remove_client_socket(client_socket);
            pthread_exit(NULL);
        }
        EVP_PKEY_free(priv_key);
        #ifdef DEBUG
        printf("Chiave decifrata: ");
        myprintbytes(key, AES_KEY_SIZE);  // Stampa la chiave decifrata
        #endif
        clear_buffer(buffer, BUFFER_SIZE);
      
        // Lettura dell'IV
        valread = read(client_socket, buffer, AES_BLOCK_SIZE);
        if (valread > 0){
            myByteCopy(iv, buffer, AES_BLOCK_SIZE);
            #ifdef DEBUG
            printf("IV ricevuto: ");
            myprintbytes(iv, AES_BLOCK_SIZE);  // Stampa l'IV ricevuto
            #endif
        
            // Lettura dei messaggi
            clear_buffer(buffer, BUFFER_SIZE);
            int loggedin = 0; // 1 se l'utente è loggato, 0 se non è loggato
            char logged_nickname[small_size]={0}; //nickname attalmente loggato
            while ((valread = read(client_socket, buffer, BUFFER_SIZE)) > 0){
                #ifdef DEBUG
                printf("valread: %d\n",valread);
                myprintbytes2(buffer); 
                #endif
                unsigned char *s2;
                MALLOC(s2, valread + 1);
                //decifro
                clear_buffer(s2, valread + 1);
                int len = decrypt(buffer, valread, key, iv, s2) ;
                char *s;
                MALLOC(s, len * 8);
                clear_buffer(s, len * 8);
                convertByteToStr(s, s2, len*8);
                #ifdef DEBUG
                printf("ricevuto: ");
                puts(s); 
                printf("%s\n",s);
                #endif
                
                //Divido la stringa in due, in modo da vedere l'operazione da eseguire
                char operation[small_size];
                char body[BUFFER_SIZE];
                split_in_two(s, "::", operation, body, small_size, BUFFER_SIZE);
                #ifdef DEBUG
                printf("operazionze: %s\nIl resto del testo: %s\n", operation, body);         
                #endif
                clear_buffer(buffer, BUFFER_SIZE);
                myfree(&s);
                free(s2);
                
                /*A seconda della operazione da eseguire verifico i vari casi*/
                //Caso "register"
                if(strcmp(operation, "register")==0 && loggedin == 0){
                  //printf("Adesso farò la registrazione\n");
                  char email[small_size] = {0};
                  char body2[large_size] = {0};
                  char nickname[small_size] = {0};
                  char password[small_size] = {0};

                  if (!(split_in_two(body, "::", email, body2, small_size, large_size)|| email[0]== '\0')){
                      perror("Errore sulla split, possibile attacco in corso");
                  }else
                  if (!(split_in_two(body2, "::", nickname, password, small_size, small_size) || nickname[0] == '\0' || password[0] == '\0')){
                      perror("Errore sulla split, possibile attacco in corso");
                  }else{
                    #ifdef DEBUG
                    printf("email: %s\nnichname: %s\npassword: %s\n", email, nickname, password);
                    #endif
                    
                    /* 
                        Simulo l'invio della sfida (numero casuale di 6 cifre) per email e attendo la risposta. 
                        Non invio la sfida per email, stampo il valore sul terminale del server.
                        Se l'utente supera la sfida allora:
                        - verifico che il nickname o l'email non siano già presenti nel file utenti.
                        - salvo il nuovo utente nel file e/o invio la risposta al client
                    */
                    
                    //generazione numero casuale di 6 cifre
                    int random_number = generate_random_6_digit_number();
                    printf("Numero casuale di 6 cifre: %d\n", random_number);
                    //A questo punto dovrei mandare la sfida all'email inserita, ed attendere la risposta.
                    //Ricevo il valore dal client e verifico se è corretto
                    clear_buffer(buffer, BUFFER_SIZE);
                    if ((valread = read(client_socket, buffer, BUFFER_SIZE)) > 0){
                      unsigned char *n_sfida;
                      MALLOC(n_sfida, valread + 1);
                      clear_buffer(n_sfida, valread + 1);
                      decrypt(buffer, valread, key, iv, n_sfida) ;
                      int num = 0;
                      if(IsNumber((char*)n_sfida)){
                        num = atoi((char *)n_sfida);
                      }
                      if(num > 0 && count_digits(num) == 6){
                        //verifico se il numero è corretto
                        if (random_number == num){
                          //La sfida è superata, proseguo verificando se email o nickname sono già presenti nel file utenti.txt
                          #ifdef DEBUG
                          printf("Sfida superata\n");
                          #endif
                          int lines_read = 0;
                          pthread_mutex_lock(&file_users_lock); 
                          char **all_users = load_all_entries_from_file(file_utenti, &lines_read);
                          if (all_users){
                            int bool_nick=0, bool_email = 0; //valori booleani che indicano se il nickname o l'email sono già presenti
                            int bool_error = 0;  //in caso di errore
                            #ifdef DEBUG
                            printf("Tutti gli utenti(%d):\n", lines_read);
                            #endif
                            for (int i = 0; i < lines_read; i++) {
                              #ifdef DEBUG
                              printf("%s\n", all_users[i]);
                              #endif
                              //confronto nickname o email ricevuti con quelli presenti nel file
                              char user_email[small_size] = {0};
                              char user_nickname[small_size] = {0};
                              char user_salthex[SALT_LEN] = {0};
                              char user_hashpasswd[HASH_LEN] = {0};
                              if(split_body(all_users[i], user_email, user_nickname, user_salthex, user_hashpasswd) == 0){
                                perror("Errore durante la lettura del file utenti");
                                bool_error = 1;
                              }
                              else{
                                if(user_email[0] != '\0' && strcmp(user_email, email) == 0)
                                  bool_email = 1;
                                if(user_nickname[0] != '\0' && strcmp(user_nickname, nickname) == 0)
                                  bool_nick = 1;
                              }
                              free(all_users[i]);
                            }
                            free(all_users);
                            if(bool_error == 1){
                              printf("Errore nella lettura degli utenti dal file.\n");  
                              send_encrypted_message(client_socket, key, iv, "Errore durante la registrazione");
                            }
                            else
                            //Il nickname o l'email non sono presenti nel file utenti.txt, proseguo con la registrazione
                              if(bool_nick == 0 && bool_email == 0){
                                  //riscrivo il body come email::nickname::salt::hash_password
                                  clear_buffer(body, BUFFER_SIZE);
                                  if (rewrite_body(body, email, nickname, password) == 0){
                                    printf("Errore riscrittura dei dati durante la registrazione");
                                    send_encrypted_message(client_socket, key, iv, "Errore durante la registrazione");
                                  }
                                  else{
                                    //La registrazione è andata a buon fine!
                                    append_string_to_file(file_utenti, body);
                                    send_encrypted_message(client_socket, key, iv, "La tua iscrizione è andata a buon fine");
                                  }
                              }
                              else{
                                //nickname o email sono già presenti nel file utenti.txt, l'utente non viene registrato
                                printf("email o nickname già presenti\n");  
                                send_encrypted_message(client_socket, key, iv, "Errore durante la registrazione, email o nickname già presenti");
                              }
                          } else {
                            printf("Errore nel caricamento degli utenti dal file.\n");  
                            send_encrypted_message(client_socket, key, iv, "Errore durante la registrazione");
                          }
                          pthread_mutex_unlock(&file_users_lock); 
                        }else{
                          //Il valore della sfida non è superata, l'utente non viene registrato.
                          //Invio la risposta al client
                          #ifdef DEBUG
                          printf("Sfida non superata\n");
                          #endif
                          send_encrypted_message(client_socket, key, iv, "Sfida non superata");
                        }
                      }
                      else{
                        //Sfida non superata, non hai inserito 6 cifre 
                        //(probabile attacco in corso, perchè in condizioni normali questo caso non si verifica mai)
                        printf("Sfida non superata, probabile attacco in corso\n");
                      }
                      free(n_sfida);
                    }
                    else{
                        #ifdef DEBUG
                        printf("Sfida non superata, non ho ricevuto il valore della sfida\n");
                        #endif
                    }
                  }
                }
                else 
                  // Caso "login"
                  if (strcmp(operation, "login") == 0 && loggedin == 0) {
                    //printf("Adesso farò il login...\n");
                    char nickname[small_size] = {0};
                    char password[small_size] = {0};

                    // Ricopio il body in nickname e password
                    if (login_split_body(body, nickname, password) == 0 || nickname[0] == '\0' || password[0] == '\0') {
                      perror("Errore durante la lettura dei dati");
                    } else {
                      // Lo split è andato bene, continua il login...
                      int lines_read = 0;
                      pthread_mutex_lock(&file_users_lock);
                      char **all_users = load_all_entries_from_file(file_utenti, &lines_read);
                      pthread_mutex_unlock(&file_users_lock);

                      if (all_users) {
                        int bool_nick = 0;  // Indica se il nickname è presente nel file
                        int bool_error = 0; // Indica un errore nella lettura dei dati
                        #ifdef DEBUG
                        printf("Tutti gli utenti (%d):\n", lines_read);
                        #endif

                        char user_email[small_size] = {0};
                        char user_nickname[small_size] = {0};
                        char user_salthex[SALT_LEN * 2 + 1] = {0}; // Salt memorizzato nel file
                        char user_hashpasswd[HASH_LEN * 2 + 1] = {0}; // Hash memorizzato nel file

                        for (int i = 0; i < lines_read; i++) {
                          #ifdef DEBUG
                          printf("%s\n", all_users[i]);
                          #endif
                          clear_buffer(user_nickname, small_size);

                          if (split_body(all_users[i], user_email, user_nickname, user_salthex, user_hashpasswd) == 0) {
                            perror("Errore durante la lettura del file utenti");
                            bool_error = 1;
                            break; // Esci dal ciclo in caso di errore
                          }

                          if (user_nickname[0] != '\0' && strcmp(user_nickname, nickname) == 0) {
                            bool_nick = 1;
                            break; // Esci dal ciclo se trovi il nickname
                          }
                        }

                        // Libera la memoria di all_users[i]
                        for (int i = 0; i < lines_read; i++) {
                          free(all_users[i]);
                        }
                        free(all_users);

                        // Gestione degli errori o condizioni finali
                        if (bool_error == 1) {
                          printf("Errore nella lettura degli utenti dal file\n");
                          send_encrypted_message(client_socket, key, iv, "Errore durante le operazioni di login");
                        } else if (bool_nick == 1) {
                        // Il nickname è presente nel file utenti.txt, prosegui con il login
                        if (verify_password_with_salt(password, user_salthex, user_hashpasswd) == 1) {
                          loggedin = 1;
                          strncpy(logged_nickname, user_nickname, small_size);
                          send_encrypted_message(client_socket, key, iv, "LOGIN_OK");
                          printf("Login dell'utente %s effettuato\n", logged_nickname);
                          } else {
                            // Password errata
                            send_encrypted_message(client_socket, key, iv, "Errore durante il login, password errata");
                            printf("Errore durante il login, password errata\n");
                          }
                        } else {
                          // Nickname non presente nel file utenti.txt
                          send_encrypted_message(client_socket, key, iv, "Errore durante il login, l'utente non è registrato");
                          printf("Errore durante il login, l'utente non è registrato\n");
                        }
                      } else {
                        printf("Errore nel caricamento degli utenti dal file.\n");
                        send_encrypted_message(client_socket, key, iv, "Errore durante le operazioni di login");
                      }
                    }
                  }
                  else
                    //Caso 'Logout'
                    if(loggedin == 1 && strcmp(operation, "logout") == 0){
                      loggedin = 0;
                      clear_buffer(logged_nickname, small_size);
                      printf("Logout eseguito\n");
                    }
                    else
                      //Caso 'Add'
                      //Eseguo lo split di autore, titolo e testo per verificare se ho ricevuto il messaggio nel formato corretto.
                      //Ma in realtà non servirebbe fare lo split per salvare il post nel file posts.txt
                      if(strcmp(operation, "add") == 0 && loggedin == 1){
                        #ifdef DEBUG
                        printf("Ricevuto comando add\n");
                        #endif
                        char autore[small_size] ={0};
                        char titolo[large_size]={0};
                        char testo[post_testo_size]={0};
                        //ricopio il body in autore, titolo e testo
                        if (add_split_body(body, autore, titolo, testo)==0 || autore[0] == '\0' || strcmp(autore, logged_nickname) != 0 || titolo[0] == '\0' || testo[0] == '\0'){
                          perror("Errore durante la lettura dei dati, possibile attacco in corso");
                          send_encrypted_message(client_socket, key, iv, "Errore durante il salvataggio del post");
                        }
                        else{
                          /*
                            Il post è nel formato corretto,
                            salvo il post nel file posts.txt,
                            il post è salvato nel formato id::autore::titolo::testo
                          */
                          //genera l'ID
                          char id[ID_LENGTH +1];
                          if (genera_id(id, ID_LENGTH + 1) == 1){
                            //aggiungo l'ID al post
                            char post[BUFFER_SIZE] = {0};
                            myconcat(post, BUFFER_SIZE, id, "::", body);
                            //salva il post nel file posts.txt
                            pthread_mutex_lock(&file_posts_lock); 
                            append_string_to_file(file_post, post);
                            pthread_mutex_unlock(&file_posts_lock); 
                            printf("Post %s aggiunto al BBS\n", id);  
                            send_encrypted_message(client_socket, key, iv, "Il post è stato aggiunto al BBS");
                          } else {
                            printf("Errore durante la generazione dell'ID del post\n");  
                            send_encrypted_message(client_socket, key, iv, "Errore durante il salvataggio del post");
                          }
                          
                        }
                      } else 
                        //Caso  'List' 
                        if(strcmp(operation, "list") == 0 && loggedin == 1){
                          #ifdef DEBUG
                          printf("Ricevuto comando list\n");
                          #endif
                          int num_posts = 0;
                          if(IsNumber((char*)body)){
                            num_posts = atoi((char *)body);
                          }
                          if(num_posts > 0 && count_digits(num_posts) < 4){
                            //carico e invio al client gli ultimi n post
                            pthread_mutex_lock(&file_posts_lock);
                            int posts_read = 0;
                            char** posts_lines = load_last_entries_from_file(file_post, num_posts, &posts_read);
                            if (posts_lines == NULL || posts_read == 0) {
                                printf("Errore durante la lettura del file posts.\n");
                                send_encrypted_message(client_socket, key, iv, "Non è stato possibile caricare i post a causa di un errore");
                            }else{
			    //sono state effettivamente lette lines_read post
			      char *post;
			      MALLOC(post, BUFFER_SIZE);
		              for (int i = posts_read - 1 ; i >= 0; i--) {
		                clear_buffer(post, BUFFER_SIZE);
		                myconcat(post, BUFFER_SIZE, "LIST", "::", posts_lines[i]);
		                #ifdef DEBUG
                                //post[strlen(post)]='\0';  
		                printf("Invio del post %d: %s\n", i, post);
		                #endif
		              	send_encrypted_message(client_socket, key, iv, post);
		                free(posts_lines[i]); // Liberazione della memoria per ogni riga
		                clear_buffer(post, BUFFER_SIZE);
		                sleep(0.5); /*
		                            sleep necessario altrimenti non so come mai mi si accavallano i messaggi al lato client.
		                            Immagino che il problema sia che il buffer al lato server venga sovrastitto prima che
		                            al lato client si faccia in tempo a leggere. Per risolvere avrei potuto implementare
		                            qualcosa tipo il protollo SYN-ACK.
		                            */
		              }
		              free(post);
		            }
                            free(posts_lines); 
                            pthread_mutex_unlock(&file_posts_lock); 
                          }
                          else{
                            printf("Errore durante la lettura del valore n, probabile attacco in corso\n");  
                            send_encrypted_message(client_socket, key, iv, "Non è stato possibile caricare i post a causa di un errore");
                          }
                          
                        } else 
                          //Caso 'Get' 
                          if(strcmp(operation, "get") == 0 && loggedin == 1){
                            #ifdef DEBUG
                            printf("Ricevuto comando get\n");
                            #endif
                            char *serched_post;
                            pthread_mutex_lock(&file_posts_lock); 
                            serched_post = find_post_by_id(file_post, body);
                            if(serched_post != NULL){
                              char *post;
			      MALLOC(post, BUFFER_SIZE);
                              myconcat(post, BUFFER_SIZE, "GET", "::", serched_post);
		              send_encrypted_message(client_socket, key, iv, post);
		              free(serched_post); 
		              free(post);
                            }
                            else
                              send_encrypted_message(client_socket, key, iv, "Post non trovato");
                            pthread_mutex_unlock(&file_posts_lock); 
                          } else {
                            printf("Operazione non riconosciuta o non valida\n");
                          }
                clear_buffer(buffer, BUFFER_SIZE);
            }
        }
    }
    
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    printf("Chiusura connessione con client thread %ld\n", pthread_self());
    
    close(client_socket);
    remove_client_socket(client_socket);

    pthread_exit(NULL);
}


static void *sigHandler(void *arg) {
    sigset_t *set = (sigset_t*)arg;
    for (;;) {
        int sig;
        int r = sigwait(set, &sig);
        if (r != 0) {
            errno = r;
            perror("FATAL ERROR 'sigwait'");
            return NULL;
        }

        switch(sig) {
            case SIGINT:
            case SIGTERM:
            case SIGQUIT:
            case SIGHUP:
                atomic_store(&close_server, 1);
                shutdown(server_fd, SHUT_RDWR);
                sleep(10);//necessario, sennò mi risultano degli errori di segmentazione che non riesco a risolvere
                #ifdef DEBUG
                printf("Server: segnale ricevuto, chiusura in corso...\n");
                #endif
                break;
            default:
                break; 
        }
        break;
    }
    return NULL;	   
}

int main(int argc, char* argv[]) {

    pid_t pid = fork();
    
    if (pid == 0) {
        execl("./genera_rsa_keys", "./genera_rsa_keys", NULL); // Genera le chiavi RSA
        perror("Errore nella execl");
    } else if (pid > 0) {
      int new_socket;
      struct sockaddr_in address; 
      int opt = 1; 
      int addrlen = sizeof(address); 

      sigset_t mask;
      sigemptyset(&mask);
      sigaddset(&mask, SIGINT); 
      sigaddset(&mask, SIGQUIT);
      sigaddset(&mask, SIGTERM); 
      sigaddset(&mask, SIGHUP);     
      if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) {
          fprintf(stderr, "FATAL ERROR\n");
          abort();
      }

      struct sigaction s;
      memset(&s, 0, sizeof(s));    
      s.sa_handler = SIG_IGN;
      if (sigaction(SIGPIPE, &s, NULL) == -1) {   
          perror("sigaction");
          abort();
      } 

      pthread_t sighandler_thread;
      if (pthread_create(&sighandler_thread, NULL, sigHandler, &mask) != 0) {
          fprintf(stderr, "errore nella creazione del signal handler thread\n");
          abort();
      }

      printf("Server\n");

      if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) { 
          perror("socket failed");
          exit(EXIT_FAILURE);
      } 

      if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) { 
          perror("setsockopt");
          exit(EXIT_FAILURE);
      } 

      address.sin_family = AF_INET; 
      address.sin_addr.s_addr = INADDR_ANY; 
      address.sin_port = htons(PORT); 

      if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
          perror("bind failed");
          exit(EXIT_FAILURE);
      } 

      if (listen(server_fd, 1) < 0) { 
          perror("listen");
          exit(EXIT_FAILURE);
      }

      while ((atomic_load(&close_server) == 0)) {
          printf("Listening...\n");
          if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) { 
              perror("Chiusura socket");
              close(new_socket);
          }
          else{
            printf("Client connected...\n");
            if((atomic_load(&close_server) == 0)){
              pthread_mutex_lock(&client_mutex);
              if (client_count < MAX_CLIENTS) {
                  client_sockets[client_count] = new_socket;
                  pthread_create(&client_threads[client_count], NULL, socketThread, &new_socket);
                  client_count++;
              } else {
                  printf("Troppi client connessi!\n");
                  close(new_socket);
              }
              pthread_mutex_unlock(&client_mutex);
            }
          }
      }	
      
      // Prima di chiudere il server, attendi che tutti i thread dei client finiscano
      for (int i = 0; i < thread_count; i++) {
          if(pthread_join(client_threads[i], NULL) != 0){
            fprintf(stderr, "Error joining clients_thread\n");
          }
      }
      
      notify_and_close_all_clients();
      
      //termino il signal handler thread
      pthread_cancel(sighandler_thread); 
      if (pthread_join(sighandler_thread, NULL) != 0) {
        fprintf(stderr, "Error joining sighandler_thread\n");
      }
      
      close(server_fd);
      
    } else {
      // Errore nella fork
      perror("Errore nella fork");
    }
    return 0;
}
