CC = gcc
CFLAGS += -std=c99 -Wall -Werror -g -D_GNU_SOURCE
LIBS = -lpthread -lssl -lcrypto

.PHONY: all client server keys clean reset debug

all: client server keys

client:
	$(CC) $(CFLAGS) client_folder/Client.c $(LIBS) -o client

server:
	$(CC) $(CFLAGS) server_folder/Server.c $(LIBS) -o server

keys:
	$(CC) $(CFLAGS) server_folder/Genera_RSA_Keys.c $(LIBS) -o genera_rsa_keys

clean:
	rm -f client server genera_rsa_keys

reset:
	rm -f client server genera_rsa_keys \
		shared_folder/public_key.pem \
		server_folder/private_key.pem \
		server_folder/counter.txt \
		server_folder/posts.txt \
		server_folder/utenti.txt

debug:
	rm -f client server genera_rsa_keys
	$(CC) $(CFLAGS) -DDEBUG server_folder/Server.c $(LIBS) -o server
	$(CC) $(CFLAGS) -DDEBUG client_folder/Client.c $(LIBS) -o client
	make keys



