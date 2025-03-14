#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H
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

STATUS generate_token(token token_, size_t token_size);
void compute_token_hash(const token token_, size_t token_size, token_hash token_hash_);
STATUS constant_time_compare(const token_hash a, const token_hash *b, size_t len);
STATUS verify_token(int id, const token received_token);

void print_token_hash(token_hash token_hash);
#endif




