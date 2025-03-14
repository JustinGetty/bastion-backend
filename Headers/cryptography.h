#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <bastion_data.h>

/*
    PROCESS:
    1. generate random token using RAND_bytes()
    2. hash token using SHA-256
    3. Store that hash as a blob in sqlite table
    4. when response from mobile comes:
        - Decrypt message with asym/sym keys
        - Compute the deterministic hash of that token
        - Retrieve token hash from DB
        - use CRYPTO_memcmp() to check for match
 */

STATUS generate_token(unsigned char *token, size_t token_size);
void compute_token_hash(const unsigned char *token, size_t token_size, unsigned char *hash);
int constant_time_compare(const unsigned char *a, const unsigned char *b, size_t len);
int verify_token(int id, const unsigned char *received_token);







