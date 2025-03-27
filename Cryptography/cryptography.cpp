#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include "../Headers/cryptography.h"
#include <bastion_data.h>
#include "../Headers/databaseq.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>

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

//STATUS constant_time_compare(const token_hash a, const token_hash *b, size_t len);
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

STATUS generate_symmetric_key(unsigned char *key, size_t key_size) {
    if (RAND_bytes(key, key_size) != 1) {
        fprintf(stderr, "Error generating symmetric key\n");
        return SYM_KEY_GEN_FAILURE;
    }
    return SUCCESS;
}

STATUS sym_decrypt(const unsigned char *ciphertext, int *ciphertext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len, plaintext_len = 0;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating EVP_CIPHER_CTX\n");
        return SYM_DECRYPT_FAILURE;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_DECRYPT_FAILURE;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, *ciphertext_len) != 1) {
        fprintf(stderr, "Error during decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_DECRYPT_FAILURE;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "Error during final decryption (possibly padding issue)\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_DECRYPT_FAILURE;
    }
    plaintext_len += len;

    *ciphertext_len = plaintext_len;

    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}


STATUS sym_encrypt(const unsigned char *plaintext, int *plaintext_len,
                   const unsigned char *key, const unsigned char *iv,
                   unsigned char *ciphertext, int *ciphertext_len)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error creating EVP_CIPHER_CTX\n");
        return SYM_ENCRYPT_FAILURE;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_ENCRYPT_FAILURE;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, *plaintext_len) != 1) {
        fprintf(stderr, "Error during encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_ENCRYPT_FAILURE;
    }
    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "Error during final encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_ENCRYPT_FAILURE;
    }
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}


//this shit simulates main to test crypto functions
int test_as_main() {
    sym_key key;
    sym_iv iv;

    if (generate_symmetric_key(key, KEY_SIZE) != SUCCESS) {
        std::fprintf(stderr, "Symmetric key generation failed\n");
        return -1;
    }

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        std::fprintf(stderr, "IV generation failed\n");
        return -1;
    }

    std::printf("Symmetric Key:\n");
    print_hex(key, KEY_SIZE);
    std::printf("IV:\n");
    print_hex(iv, IV_SIZE);

    asym_key_struct asym_keys{};
    if (generate_asym_keypair(&asym_keys) != SUCCESS) {
        std::cerr << "Failed to generate asymmetric key pair\n";
        return -1;
    }
    std::cout << "PRIVATE KEY LENGTH: " <<asym_keys.priv_key_len << "\n";

    priv_key_w_length priv_key_full{};
    memcpy(priv_key_full.priv_key, asym_keys.priv_key, asym_keys.priv_key_len);
    priv_key_full.priv_key_len = asym_keys.priv_key_len;
    STATUS asym_priv_store_stat = store_user_private_key(1, &priv_key_full);

    token auth_token{};
    if (generate_token(auth_token, TOKEN_SIZE) != SUCCESS) {
        std::fprintf(stderr, "Auth token generation failed\n");
        return -1;
    }
    std::printf("Auth Token:\n");
    print_hex(auth_token, TOKEN_SIZE);

    //compute hash of token, store it
    token_hash computed_hash{};
    compute_token_hash(auth_token, TOKEN_SIZE, computed_hash);
    std::printf("Computed Token Hash:\n");
    print_token_hash(computed_hash);


    STATUS store_token_hash_stat = store_token_hash(1, computed_hash, TOKEN_SIZE);
    std::cout << "Store token hash status: " << store_token_hash_stat << "\n";
    if (store_token_hash_stat != SUCCESS) {
        std::cout << "ERROR STORING HASH, EXITING\n";
        return 1;
    }

    //encrypt hash with sym key
    int hash_len = HASH_SIZE;
    unsigned char sym_encrypted[256] = {0};
    int sym_encrypted_len = 0;
    if (sym_encrypt(computed_hash, &hash_len,
                    key, iv,
                    sym_encrypted, &sym_encrypted_len) != SUCCESS)
    {
        std::fprintf(stderr, "Symmetric encryption failed\n");
        return -1;
    }
    std::printf("Symmetric Encrypted Token Hash:\n");
    print_hex(sym_encrypted, sym_encrypted_len);

    //encrypt sym-enc hash with pub asym key
    unsigned char asym_encrypted_hash[ASYM_SIZE] = {0};
    int asym_encrypted_hash_len = 0;
    if (encrypt_with_pub_key(asym_keys.pub_key, asym_keys.pub_key_len,
                             sym_encrypted, sym_encrypted_len,
                             asym_encrypted_hash, &asym_encrypted_hash_len) != SUCCESS)
    {
        std::fprintf(stderr, "Asymmetric encryption of token hash failed\n");
        return -1;
    }
    std::printf("Asymmetric Encrypted (wrapped token hash):\n");
    print_hex(asym_encrypted_hash, asym_encrypted_hash_len);

    //encrypt sym key and iv with asym pub key
    unsigned char key_iv[KEY_SIZE + IV_SIZE] = {0};
    std::memcpy(key_iv, key, KEY_SIZE);
    std::memcpy(key_iv + KEY_SIZE, iv, IV_SIZE);

    unsigned char asym_encrypted_keyiv[ASYM_SIZE] = {0};
    int asym_encrypted_keyiv_len = 0;
    if (encrypt_with_pub_key(asym_keys.pub_key, asym_keys.pub_key_len,
                             key_iv, KEY_SIZE + IV_SIZE,
                             asym_encrypted_keyiv, &asym_encrypted_keyiv_len) != SUCCESS)
    {
        std::fprintf(stderr, "Asymmetric encryption of symmetric key/IV failed\n");
        return -1;
    }
    std::printf("Asymmetric Encrypted (symmetric key + IV):\n");
    print_hex(asym_encrypted_keyiv, asym_encrypted_keyiv_len);

    unsigned char decrypted_keyiv[KEY_SIZE + IV_SIZE] = {0};
    int decrypted_keyiv_len = 0;
    if (decrypt_with_private_key(asym_keys.priv_key, asym_keys.priv_key_len,
                                 asym_encrypted_keyiv, asym_encrypted_keyiv_len,
                                 decrypted_keyiv, &decrypted_keyiv_len) != SUCCESS)
    {
        std::fprintf(stderr, "Asymmetric decryption of key/IV failed\n");
        return -1;
    }
    if (decrypted_keyiv_len != (KEY_SIZE + IV_SIZE)) {
        std::fprintf(stderr, "Decrypted key/IV length mismatch\n");
        return -1;
    }
    unsigned char recovered_key[KEY_SIZE] = {0};
    unsigned char recovered_iv[IV_SIZE] = {0};
    std::memcpy(recovered_key, decrypted_keyiv, KEY_SIZE);
    std::memcpy(recovered_iv, decrypted_keyiv + KEY_SIZE, IV_SIZE);
    std::printf("Recovered Symmetric Key:\n");
    print_hex(recovered_key, KEY_SIZE);
    std::printf("Recovered IV:\n");
    print_hex(recovered_iv, IV_SIZE);


    //get asym key back from db
    asym_key_struct asym_keys_from_db{};
    memcpy(asym_keys_from_db.pub_key, asym_keys.pub_key, asym_keys.pub_key_len);

    priv_key_w_length private_key_from_db{};
    STATUS get_priv_key_stat = get_user_private_key(1, &private_key_from_db);
    if (get_priv_key_stat != SUCCESS) {
        std::cout << "Error getting user private key: " << get_priv_key_stat << "\n";
        return 1;
    }

    memcpy(asym_keys_from_db.priv_key, private_key_from_db.priv_key, asym_keys_from_db.priv_key_len);
    asym_keys_from_db.priv_key_len = private_key_from_db.priv_key_len;
    std::cout << "PRIVATE KEY:\n";
    print_private_key(private_key_from_db);

    unsigned char decrypted_sym_encrypted[256] = {0};
    int decrypted_sym_encrypted_len = 0;
    if (decrypt_with_private_key(asym_keys_from_db.priv_key, asym_keys_from_db.priv_key_len,
                                 asym_encrypted_hash, asym_encrypted_hash_len,
                                 decrypted_sym_encrypted, &decrypted_sym_encrypted_len) != SUCCESS)
    {
        std::fprintf(stderr, "Asymmetric decryption of wrapped token hash failed\n");
        return -1;
    }
    std::printf("Recovered Symmetric-Encrypted Token Hash:\n");
    print_hex(decrypted_sym_encrypted, decrypted_sym_encrypted_len);

    unsigned char final_decrypted_hash[HASH_SIZE] = {0};
    if (sym_decrypt(decrypted_sym_encrypted, &decrypted_sym_encrypted_len,
                    recovered_key, recovered_iv,
                    final_decrypted_hash) != SUCCESS)
    {
        std::fprintf(stderr, "Symmetric decryption of token hash failed\n");
        return -1;
    }
    std::printf("Final Decrypted Token Hash:\n");
    print_token_hash(final_decrypted_hash);

    if (constant_time_compare(final_decrypted_hash, computed_hash, HASH_SIZE) == SUCCESS) {
        std::printf("Token verification successful!\n");
    } else {
        std::printf("Token verification failed!\n");
    }

    return 0;
}

int fake_main() {
    asym_key_struct keypair{};
    if (generate_asym_keypair(&keypair) != SUCCESS) {
        std::cerr << "Failed to generate asymmetric key pair." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Asymmetric key pair generated." << std::endl;

    priv_key_w_length priv_key_struct{};
    std::memcpy(priv_key_struct.priv_key, keypair.priv_key, keypair.priv_key_len);
    priv_key_struct.priv_key_len = keypair.priv_key_len;

    std::cout << "Private key length: " << priv_key_struct.priv_key_len << std::endl;

    if (store_user_private_key(1, &priv_key_struct) != SUCCESS) {
        std::cerr << "Failed to store private key." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Private key stored in the database." << std::endl;

    const char *message = "Hello, World!";
    int message_len = std::strlen(message);
    unsigned char encrypted[ASYM_SIZE] = {0};
    int encrypted_len = 0;
    if (encrypt_with_pub_key(keypair.pub_key, keypair.pub_key_len,
                             reinterpret_cast<const unsigned char*>(message), message_len,
                             encrypted, &encrypted_len) != SUCCESS) {
        std::cerr << "Encryption with public key failed." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Message encrypted using the public key." << std::endl;

    priv_key_w_length retrieved_priv_key{};
    if (get_user_private_key(1, &retrieved_priv_key) != SUCCESS) {
        std::cerr << "Failed to retrieve private key from the database." << std::endl;
        return EXIT_FAILURE;
    }
    std::cout << "Private key retrieved from the database." << std::endl;

    unsigned char decrypted[ASYM_SIZE] = {0};
    int decrypted_len = 0;
    if (decrypt_with_private_key(retrieved_priv_key.priv_key, retrieved_priv_key.priv_key_len,
                                encrypted, encrypted_len,
                                decrypted, &decrypted_len) != SUCCESS) {
        std::cerr << "Decryption with private key failed." << std::endl;
        return EXIT_FAILURE;
    }
    if (decrypted_len < ASYM_SIZE) {
        decrypted[decrypted_len] = '\0';
    }
    std::cout << "Decrypted message: " << decrypted << std::endl;

    return EXIT_SUCCESS;
}