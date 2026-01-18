# Secure Bulletin Board System (BBS)

## Overview

This project implements a **secure Bulletin Board System (BBS)** developed in **C** using the **OpenSSL** library (without relying on OpenSSL TLS APIs).
The system follows a **client–server architecture**, where a centralized server manages users, authentication, and posts, while multiple clients can connect concurrently.

The project was developed for the course **Foundations of Cybersecurity / Applied Cryptography (a.a. 2023–24)** and focuses on secure communication, credential protection, and concurrency management.

---

## Features

### User Management

* User registration with **email, nickname, and password**
* Login and logout functionality
* Passwords are **never stored or transmitted in clear text**
* Passwords are stored as **hash + random salt**

### Bulletin Board Operations

* `List(n)` – list the latest `n` messages
* `Get(mid)` – retrieve a message by ID
* `Add(title, author, body)` – add a new message

Each message contains:

* Unique identifier
* Title
* Author (nickname)
* Body

---

## Security Properties

The system is designed to satisfy the following security requirements:

* **Confidentiality** – all client–server communications are encrypted
* **Integrity** – encrypted messages prevent tampering
* **Replay protection** – each session uses a fresh symmetric key
* **Non-malleability** – malformed or manipulated messages are rejected
* **Credential protection** – passwords are hashed with salt
* **Partial Perfect Forward Secrecy (PFS)** – RSA keys are regenerated at each server startup

Note: Perfect Forward Secrecy in the strict sense is not fully achieved, since RSA is used for key exchange. A Diffie-Hellman-based exchange would be required for full PFS.

---

## Cryptographic Design

* **RSA**

  * Used to encrypt the AES session key
  * A new RSA key pair is generated at every server startup

* **AES**

  * Used for all communication after key exchange
  * Each client session uses a unique AES key and IV

* **Hashing**

  * Passwords are stored as `salt + hash(password)`

---

## Architecture

### Server

* Centralized BBS server
* Multi-threaded (one thread per client)
* Handles:

  * User registration and authentication
  * Secure session management
  * Post storage and retrieval
* Graceful shutdown via signal handling (`SIGINT`, `SIGTERM`, etc.)

### Client

* Multi-threaded:

  * One thread for sending messages
  * One thread for receiving messages
* Asynchronous communication
* Automatic disconnection after inactivity timeout

---

## Folder Structure

* `client/` – client source code
* `server/` – server source code, data files, private key
* `shared/` – shared code and public key
* `Makefile`
* `README.md`

---

## Dependencies

* GCC compiler
* OpenSSL library

### Install OpenSSL (Ubuntu/Debian)

Command: `sudo apt install openssl libssl-dev`

---

## Compilation

The project includes a `Makefile` with the following commands:

| Command       | Description                                   |
| ------------- | --------------------------------------------- |
| `make all`    | Compile client, server, and RSA key generator |
| `make client` | Compile only the client                       |
| `make server` | Compile only the server                       |
| `make keys`   | Compile RSA key generator                     |
| `make debug`  | Compile with debug flags enabled              |
| `make clean`  | Remove compiled binaries                      |
| `make reset`  | Delete all keys and stored data               |

---

## Execution

### Start the Server

Command: `./server`

### Start the Client

Command: `./client`

The server must be running before starting any client.

---

## Supported Client Commands

| Command    | Description                             |
| ---------- | --------------------------------------- |
| `register` | Register a new user                     |
| `login`    | Authenticate with nickname and password |
| `logout`   | Log out from the current session        |
| `add`      | Add a new post                          |
| `list`     | List latest posts                       |
| `get`      | Retrieve a post by ID                   |
| `close`    | Close the client                        |

### Debug-only Command

* `hack` – sends raw crafted messages to the server (debug mode only)

---

## Data Storage Format

### Posts (posts.txt)

Format: `id::author::title::text`

### Users (users.txt)

Format: `email::nickname::salt::hash_password`

### Post IDs

* 4-character alphanumeric IDs
* Sequential generation (e.g., `AAAA`, `AAAB`, ...)
* Last ID stored in `counter.txt`

---

## Known Limitations

* Registration challenge is printed on the server terminal instead of being sent via email
* Perfect Forward Secrecy is not fully guaranteed
* Occasional message overlap during `list` operations due to socket timing
* No automated test suite
* Limited protection against flooding/DoS attacks

---

## Possible Improvements

* Replace RSA key exchange with Diffie-Hellman for full PFS
* Implement message acknowledgment (ACK) to avoid overlap
* Add email-based challenge delivery
* Improve DoS resistance
* Introduce structured message framing instead of sleep-based synchronization

---

## Authors

Developed as an academic project for
**Foundations of Cybersecurity / Applied Cryptography (a.a. 2023–24)**

---

## License

This project is intended for **educational purposes only**.
