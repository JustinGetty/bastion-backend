#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include "Headers/cryptography.h"
#include <bastion_data.h>
#include "Headers/databaseq.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

void print_token_hash(token_hash token_hash) {
    printf("Token Hash:\n");
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", token_hash[i]);
    }
    printf("\n");
}

void print_private_key(priv_key_w_length private_key) {
    printf("Private key: \n");
    for (int i = 0; i < private_key.priv_key_len; i++) {
        printf("%02x", private_key.priv_key[i]);
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

//check for errors
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

/* ----- ASYMMETRIC KEYS --------- */
/* Generates an RSA key pair using the EVP_PKEY API and stores the DER-encoded keys
   in fixed-length buffers provided by key_structure.
   The DER-encoded private key is in PKCS#8 format.
   Returns SUCCESS on success, or CRYPTO_FAILURE on error.
*/



STATUS generate_asym_keypair(asym_key_struct *key_structure) {
    EVP_PKEY_CTX *ctx = nullptr;
    EVP_PKEY *pkey = nullptr;
    BIGNUM *bn_e = nullptr;
    int bits = 2048;
    unsigned long e = RSA_F4;
    int priv_len = 0, pub_len = 0;
    STATUS status = SUCCESS;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        fprintf(stderr, "Error creating EVP_PKEY_CTX\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing keygen\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "Error setting RSA keygen bits\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }

    // Create and initialize the public exponent.
    bn_e = BN_new();
    if (!bn_e) {
        fprintf(stderr, "Error allocating BIGNUM for exponent\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (BN_set_word(bn_e, e) != 1) {
        fprintf(stderr, "Error setting BIGNUM word for exponent\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    // In OpenSSL 3.0, EVP_PKEY_CTX_set_rsa_keygen_pubexp takes ownership of bn_e.
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, bn_e) <= 0) {
        fprintf(stderr, "Error setting RSA public exponent\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    // Avoid double free: set bn_e to nullptr since ownership has been transferred.
    bn_e = nullptr;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "Error generating RSA keypair\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }

    // Use temporary buffers for DER encoding.
    {
        unsigned char *tmp_priv = nullptr;
        priv_len = i2d_PrivateKey(pkey, &tmp_priv);
        if (priv_len < 0 || priv_len > ASYM_SIZE) {
            fprintf(stderr, "Error encoding private key or buffer is too small\n");
            OPENSSL_free(tmp_priv);
            status = CRYPTO_FAILURE;
            goto cleanup;
        }
        memcpy(key_structure->priv_key, tmp_priv, priv_len);
        key_structure->priv_key_len = priv_len;
        OPENSSL_free(tmp_priv);
    }

    {
        unsigned char *tmp_pub = nullptr;
        pub_len = i2d_PUBKEY(pkey, &tmp_pub);
        if (pub_len < 0 || pub_len > ASYM_SIZE) {
            fprintf(stderr, "Error encoding public key or buffer is too small\n");
            OPENSSL_free(tmp_pub);
            status = CRYPTO_FAILURE;
            goto cleanup;
        }
        memcpy(key_structure->pub_key, tmp_pub, pub_len);
        key_structure->pub_key_len = pub_len;
        OPENSSL_free(tmp_pub);
    }

    printf("Private key DER length: %d bytes\n", priv_len);
    printf("Public key DER length: %d bytes\n", pub_len);

cleanup:
    // Only free bn_e if it still exists.
    if (bn_e) BN_free(bn_e);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    return status;
}

/* Encrypts a message using an RSA public key stored as a DER-encoded blob.
   The public key is decoded using d2i_PUBKEY_ex.
   The encrypted data is written into 'encrypted', and its length is stored in 'encrypted_len_out'.
   Returns SUCCESS on success, or CRYPTO_FAILURE on error.
*/
STATUS encrypt_with_pub_key(const unsigned char *pub_blob, int pub_blob_len,
                            const unsigned char *message, int message_len,
                            unsigned char *encrypted, int *encrypted_len_out) {
    EVP_PKEY *pkey = nullptr;
    const unsigned char *p = pub_blob;
    EVP_PKEY_CTX *ctx = nullptr;
    size_t outlen = 0;
    STATUS status = SUCCESS;

    pkey = d2i_PUBKEY_ex(nullptr, &p, pub_blob_len, nullptr, nullptr);
    if (!pkey) {
        fprintf(stderr, "Error decoding public key DER\n");
        return CRYPTO_FAILURE;
    }

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        fprintf(stderr, "Error creating context for encryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing encryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "Error setting RSA padding\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    // Determine the required buffer length for encryption.
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, message, message_len) <= 0) {
        fprintf(stderr, "Error determining encrypted length\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (outlen > (size_t)ASYM_SIZE) {
        fprintf(stderr, "Encrypted data length exceeds buffer size\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_encrypt(ctx, encrypted, &outlen, message, message_len) <= 0) {
        fprintf(stderr, "Error encrypting message\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    *encrypted_len_out = (int)outlen;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return status;
}

/* Decrypts a message using an RSA private key stored as a DER-encoded blob.
   The private key is decoded using d2i_PrivateKey_ex.
   The decrypted data is written into 'decrypted', and its length is stored in 'decrypted_len_out'.
   Returns SUCCESS on success, or CRYPTO_FAILURE on error
*/
STATUS decrypt_with_private_key(const unsigned char *priv_blob, int priv_blob_len,
                                const unsigned char *encrypted, int encrypted_len,
                                unsigned char *decrypted, int *decrypted_len_out) {
    EVP_PKEY *pkey = nullptr;
    const unsigned char *p = priv_blob;
    EVP_PKEY_CTX *ctx = nullptr;
    size_t outlen = 0;
    STATUS status = SUCCESS;

    pkey = d2i_PrivateKey_ex(EVP_PKEY_RSA, nullptr, &p, priv_blob_len, nullptr, nullptr);
    if (!pkey) {
        fprintf(stderr, "Error decoding private key DER\n");
        return CRYPTO_FAILURE;
    }

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        fprintf(stderr, "Error creating context for decryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "Error initializing decryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "Error setting RSA padding\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    // Determine the required buffer length for decryption.
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted, encrypted_len) <= 0) {
        fprintf(stderr, "Error determining decrypted length\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (outlen > (size_t)ASYM_SIZE) {
        fprintf(stderr, "Decrypted data length exceeds buffer size\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(ctx, decrypted, &outlen, encrypted, encrypted_len) <= 0) {
        fprintf(stderr, "Error decrypting message\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    *decrypted_len_out = (int)outlen;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return status;
}

STATUS decrypt_user_message(int user_id, const unsigned char *encrypted, int encrypted_len, unsigned char *decrypted) {
    priv_key_w_length priv_key_full;
    get_user_private_key(user_id, &priv_key_full);
    int len_out;
    int *ptr = &len_out;
    STATUS decrypt_status = decrypt_with_private_key(priv_key_full.priv_key, priv_key_full.priv_key_len, encrypted, encrypted_len, decrypted, ptr);
    return decrypt_status;
}

/* SYMMETRIC KEYS ---------------------------------------------------*/

int main(void) {

    full_user_data *user_data;
    STATUS ret_status = get_full_user_data(1, user_data);
    if (ret_status == SUCCESS) {
        printf("retrieval success\n");
        printf("User ID: %d\n", user_data->user_id);
        printf("Username: %s\n", user_data->username);
        print_token_hash(user_data->enc_auth_token);
        print_private_key(user_data->priv_key_w_len);
    } else {
        printf("Failure");
    }

    /*
    const char *message = "Hello world!";
    int message_len = strlen(message);
    unsigned char encrypted[ASYM_SIZE] = {0};
    unsigned char decrypted[ASYM_SIZE] = {0};
    int encrypted_len = 0;
    int decrypted_len = 0;

    if (encrypt_with_pub_key(asym_keys.pub_key, asym_keys.pub_key_len,
                             (const unsigned char*)message, message_len,
                             encrypted, &encrypted_len) != SUCCESS) {
        fprintf(stderr, "Encryption failed\n");
        return -1;
    }
    printf("Encryption succeeded. Encrypted length: %d bytes\n", encrypted_len);

    printf("Encrypted text: ");
    for (int i = 0; i < encrypted_len; i++) {
        printf("%02x", encrypted[i]);
    }
    printf("\n");

    if (decrypt_with_private_key(asym_keys.priv_key, asym_keys.priv_key_len,
                                 encrypted, encrypted_len,
                                 decrypted, &decrypted_len) != SUCCESS) {
        fprintf(stderr, "Decryption failed\n");
        return -1;
    }
    decrypted[decrypted_len] = '\0';
    printf("Decrypted message: %s\n", decrypted);
    */
    return 0;
}