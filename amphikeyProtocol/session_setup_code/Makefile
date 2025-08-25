# Makefile for Hybrid PQC Secure Communication Protocol
# This Makefile compiles all components for both Authenticated and Deniable modes,
# including a benchmark version of the authenticated client.

# --- Compiler and Flags ---
CC = gcc
CFLAGS = -Wall -Wextra -O2 -DPC
LDFLAGS = -lsodium -lm -lrt # -lrt is for clock_gettime

# --- Path Variables ---
HOME := $(shell echo ~)
RACCOON_BASE = $(HOME)/raccoon/ref-c
ASCON_BASE = $(RACCOON_BASE)/ascon-c-main
PQCLEAN_BASE = $(RACCOON_BASE)/PQClean

# --- Source File Lists ---
# Shared crypto libraries
RACCOON_SRC = $(wildcard $(RACCOON_BASE)/racc_*.c) $(wildcard $(RACCOON_BASE)/*.c)
UTIL_SRC = $(wildcard $(RACCOON_BASE)/util/*.c)
PQCLEAN_SRC = $(PQCLEAN_BASE)/common/fips202.c
MLKEM_LIB = $(PQCLEAN_BASE)/crypto_kem/ml-kem-768/clean/libml-kem-768_clean.a
SHARED_CRYPTO_SRC = $(RACCOON_SRC) $(UTIL_SRC) $(PQCLEAN_SRC)

# Authenticated mode specific libraries
C1222_LIB_SRC = $(wildcard c12222/*.c)
ASCON_SRC = $(ASCON_BASE)/crypto_aead/asconaead128/ref/aead.c
AUTH_MODE_LIBS = $(C1222_LIB_SRC) $(ASCON_SRC)

# --- Include Paths ---
INCLUDE_PATHS = \
    -I. \
    -I$(RACCOON_BASE) \
    -I$(RACCOON_BASE)/inc \
    -I$(RACCOON_BASE)/util \
    -I$(PQCLEAN_BASE)/common \
    -I$(PQCLEAN_BASE)/crypto_kem/ml-kem-768/clean
AUTH_INCLUDE_PATHS = \
    $(INCLUDE_PATHS) \
    -Ic12222 \
    -I$(ASCON_BASE)/crypto_aead/asconaead128/ref \
    -I$(ASCON_BASE)/tests

# --- Defines ---
AUTH_DEFINES = -DTAG_SIZE=16 -DKEY_SIZE=16 -DNONCE_SIZE=16

# --- Targets ---
.PHONY: all authenticated deniable benchmark clean

# Default target: build everything
all: authenticated deniable benchmark

# Build authenticated mode client and server
authenticated: c1222_hybrid_server c1222_hybrid_client

# Build deniable mode components
deniable: server_keygen_executable client_keygen_executable denysender_app denyreceiver_app

# Build the benchmark client
benchmark: c1222_hybrid_client_benchmark

# --- Build Rules ---
 
# Authenticated Mode Server
c1222_hybrid_server: c1222_hybrid_server.c
	$(CC) $(CFLAGS) $(AUTH_DEFINES) -o $@ $^ \
	$(AUTH_MODE_LIBS) $(SHARED_CRYPTO_SRC) $(MLKEM_LIB) \
	$(AUTH_INCLUDE_PATHS) $(LDFLAGS)

# Authenticated Mode Client
c1222_hybrid_client: c1222_hybrid_client1.c
	$(CC) $(CFLAGS) $(AUTH_DEFINES) -o $@ $^ \
	$(AUTH_MODE_LIBS) $(SHARED_CRYPTO_SRC) $(MLKEM_LIB) \
	$(AUTH_INCLUDE_PATHS) $(LDFLAGS)

# Authenticated Mode Client (Benchmark Version)
c1222_hybrid_client_benchmark: c1222_hybrid_client_benchmark.c
	$(CC) $(CFLAGS) $(AUTH_DEFINES) -o $@ $^ \
	$(AUTH_MODE_LIBS) $(SHARED_CRYPTO_SRC) $(MLKEM_LIB) \
	$(AUTH_INCLUDE_PATHS) $(LDFLAGS)

# Deniable Mode - Server Keygen
server_keygen_executable: server_bench.c
	$(CC) $(CFLAGS) -o $@ $^ $(SHARED_CRYPTO_SRC) $(MLKEM_LIB) $(INCLUDE_PATHS) $(LDFLAGS)

# Deniable Mode - Client Keygen
client_keygen_executable: client_bench.c
	$(CC) $(CFLAGS) -o $@ $^ $(SHARED_CRYPTO_SRC) $(MLKEM_LIB) $(INCLUDE_PATHS) $(LDFLAGS)

# Deniable Mode - Sender App
denysender_app: denysender.c
	$(CC) $(CFLAGS) -o $@ $^ $(UTIL_SRC) $(PQCLEAN_SRC) $(MLKEM_LIB) $(INCLUDE_PATHS) $(LDFLAGS)

# Deniable Mode - Receiver App
denyreceiver_app: denyreceiver.c
	$(CC) $(CFLAGS) -o $@ $^ $(UTIL_SRC) $(PQCLEAN_SRC) $(MLKEM_LIB) $(INCLUDE_PATHS) $(LDFLAGS)

# Clean up build artifacts
clean:
	rm -f c1222_hybrid_server c1222_hybrid_client c1222_hybrid_client_benchmark \
	server_keygen_executable client_keygen_executable denysender_app denyreceiver_app *.o
