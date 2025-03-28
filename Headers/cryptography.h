#ifndef CRYPTOGRAPHY_H
#define CRYPTOGRAPHY_H
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

// AUTH TOKEN ------------------------------------------------------
STATUS generate_token(token token_, size_t token_size);
void compute_token_hash(const token token_, size_t token_size, token_hash token_hash_);
STATUS constant_time_compare(const token_hash a, const token_hash b, size_t len);
STATUS verify_token(int id, const token received_token);
void print_token_hash(token_hash token_hash);

// ASYMMETRIC KEYS ---------------------------------------------------
STATUS generate_asym_keypair(asym_key_struct key_structure);

STATUS encrypt_with_pub_key(const unsigned char *pub_blob, int pub_blob_len,
                const unsigned char *message, int message_len,
                unsigned char *encrypted);

STATUS decrypt_with_private_key(const unsigned char *priv_blob, int priv_blob_len,
                const unsigned char *encrypted, int encrypted_len,
                unsigned char *decrypted);

STATUS decrypt_with_private_key(const unsigned char *priv_blob, int priv_blob_len,
                                const unsigned char *encrypted, int encrypted_len,
                                unsigned char *decrypted, int *decrypted_len_out);

// Returns the total length of the DER-encoded object (header + content)
// If the blob is malformed or max_blob_size is insufficient, returns 0.



// SYMMETRIC KEY ---------------------------------------------------
STATUS generate_symmetric_key(unsigned char *key, size_t key_size);

STATUS sym_decrypt(const unsigned char *ciphertext, int *ciphertext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char *plaintext);

STATUS sym_encrypt(const unsigned char *plaintext, int *plaintext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char *ciphertext, int *ciphertext_len);

// GENERIC ----------------------------------------------------------
std::string base64_encode(const unsigned char* buffer, size_t length);
std::vector<unsigned char> base64_decode(const std::string &encoded);


// TESTSSS -------------------------------------------------------
int test_as_main();
int fake_main();
int test_sym_encode_json();
int test_full_send();

#endif




