#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include "Headers/cryptography.h"
#include <bastion_data.h>
#include "Headers/databaseq.h"

void print_token_hash(token_hash token_hash) {
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", token_hash[i]);
    }
    printf("\n");
}

STATUS generate_token(token token_, size_t token_size) {
    if (RAND_bytes(token_, token_size) != 1) {
        fprintf(stderr, "Error generating random token.\n");
        return CRYPTO_FAILURE;
    }
    return SUCCESS;
}

void compute_token_hash(const token token_, size_t token_size, token_hash token_hash_) {
    SHA256(token_, token_size, token_hash_);
}

STATUS constant_time_compare(const token_hash a, const token_hash b, size_t len) {
    if (CRYPTO_memcmp(a, b, len) == 0) {
        return SUCCESS;
    }
    return CRYPTO_FAILURE;
}

/* Verifies a token by:
   1. Retrieving the stored token hash (from a database)
   2. Computing the hash of the received token
   3. Comparing the two hashes in constant time.
   Both the stored and received tokens use fixed-width arrays.
   */
STATUS verify_token(int id, const token received_token) {
    token_hash stored_hash;
    token_hash computed_hash;

    //need to implement get_token_hash
    if (get_token_hash(id, stored_hash) != SUCCESS) {
        fprintf(stderr, "Failed to retrieve stored token hash for id %d.\n", id);
        return CRYPTO_FAILURE;
    }

    compute_token_hash(received_token, TOKEN_SIZE, computed_hash);

    if (constant_time_compare(stored_hash, computed_hash, HASH_SIZE) == SUCCESS) {
        printf("Token verification succeeded.\n");
        return SUCCESS;
    }

    printf("Token verification failed.\n");
    return VERIFICATION_FAILURE;
}

int main(void) {

    token auth_token;
    if (generate_token(auth_token, TOKEN_SIZE) != SUCCESS) {
        printf("EXIT FAILURE\n");
        return EXIT_FAILURE;
    }
    printf("Plaintext token generated:\n");
    for (int i = 0; i < TOKEN_SIZE; i++) {
        printf("%02x", auth_token[i]);
    }
    printf("\n");

    // --- Step 2: Compute a secure hash of the token.
    unsigned char token_hash[HASH_SIZE];
    compute_token_hash(auth_token, TOKEN_SIZE, token_hash);
    printf("Computed token hash:\n");
    print_token_hash(token_hash);

    STATUS post_status = store_token_hash(1, token_hash, HASH_SIZE);
    printf(post_status == SUCCESS ? "SUCCESS\n" : "FAILURE\n");

    token auth_token_out;
    STATUS get_status = get_token_hash(1, auth_token_out);
    if (get_status == SUCCESS) {
        printf("Hash token to match: \nOriginal: \n");
        print_token_hash(token_hash);

        printf("Retrieved token hash:\n");
        print_token_hash(auth_token_out);
    }
    else {
        printf("Failed to retrieve token hash.\n");
    }

    STATUS verification_status = verify_token(1, auth_token);
    printf(verification_status == SUCCESS ? "SUCCESS\n" : "FAILURE\n");


    return EXIT_SUCCESS;
}
