Hybrid PQC Secure Communication Protocol

This project implements a hybrid post-quantum secure communication protocol with two distinct operational modes: an Authenticated Mode for secure C12.22 meter data exchange and a Deniable Mode for plausibly deniable messaging.

The protocol leverages a combination of classic and post-quantum cryptographic algorithms:

    Key Encapsulation: ML-KEM (a NIST PQC standard finalist) and X25519.

    Digital Signatures: Raccoon (a NIST PQC alternate candidate).

    Authenticated Encryption: ASCON (the standard for lightweight cryptography selected by NIST).

1. Prerequisites

Before compiling, ensure you have the following installed:

    gcc compiler and standard build tools (make).

    libsodium library.

On Debian/Ubuntu, you can install these with:

sudo apt-get update
sudo apt-get install build-essential libsodium-dev

2. Directory Structure

It is critical that your directories are structured as follows for the Makefile to work correctly:

~/session_setup_code/  (Your main project folder)
├── c1222_hybrid_server.c
├── c1222_hybrid_client1.c
├── server_bench.c
├── client_bench.c
├── denysender.c
├── denyreceiver.c
├── c12222/
│   ├── ansi_c1222.c
│   ├── ... (other c1222 source and header files)
└── Makefile

~/raccoon/ref-c/          (Shared crypto libraries)
├── ascon-c-main/
├── PQClean/
├── racc_api.c
├── ... (other raccoon source and header files)

3. Compilation

A Makefile is provided to simplify the compilation of all components.

    To build everything (all clients and servers for both modes):

    make all

    To build only the Authenticated Mode client and server:

    make authenticated

    To build only the Deniable Mode components:

    make deniable

    To clean up all compiled executables and object files:

    make clean

4. Running the Applications
Mode 1: Authenticated C12.22 Communication

This mode simulates a secure session between a utility server and a smart meter.

    Start the Server: Open a terminal and run the server. It will wait for a client to connect.

    ./c1222_hybrid_server

    Run the Client: Open a second terminal and run the client. It will initiate the handshake and perform the secure data exchange.

    ./c1222_hybrid_client

Mode 2: Deniable Messaging

This mode demonstrates a plausibly deniable key exchange and messaging system.

    Generate Server Keys: In one terminal, run the server key generation utility. This will create the necessary key files.

    ./server_keygen_executable

    Generate Client Keys: In a second terminal, run the client key generation utility.

    ./client_keygen_executable

    Start the Receiver (Bob): In the first terminal, start the receiver. It will wait for a message from the sender.

    ./denyreceiver_app

    Run the Sender (Alice): In the second terminal, run the sender. It will perform the deniable handshake and send a secure message.

    ./denysender_app

