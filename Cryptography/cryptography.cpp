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
#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <cstdio>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <cctype>
#include "database_comm_v2.h"

void print_token_hash(token_hash token_hash) {
    printf("[INFO] Token Hash:\n[DATA] ");
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", token_hash[i]);
    }
    printf(".\n");
}

void print_private_key(priv_key_w_length private_key) {
    printf("[INFO] Private key: \n[DATA] ");
    for (int i = 0; i < private_key.priv_key_len; i++) {
        printf("%02x", private_key.priv_key[i]);
    }
    printf(".\n");
}

STATUS generate_token(token token_, size_t token_size) {
    if (RAND_bytes(token_, token_size) != 1) {
        fprintf(stderr, "[ERROR] Error generating random token.\n");
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
/*
STATUS verify_token(int id, const token received_token) {
    token_hash stored_hash;
    token_hash computed_hash;

    //need to implement get_token_hash
    if (get_token_hash(id, stored_hash) != SUCCESS) {
        fprintf(stderr, "[ERROR] Failed to retrieve stored token hash for id %d.\n", id);
        return CRYPTO_FAILURE;
    }

    compute_token_hash(received_token, TOKEN_SIZE, computed_hash);

    if (constant_time_compare(stored_hash, computed_hash, HASH_SIZE) == SUCCESS) {
        printf("[INFO] Token verification succeeded.\n");
        return SUCCESS;
    }

    printf("[INFO] Token verification failed.\n");
    return VERIFICATION_FAILURE;
}
*/
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
        fprintf(stderr, "[ERROR] Error creating EVP_PKEY_CTX\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "[ERROR] Error initializing keygen\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        fprintf(stderr, "[ERROR] Error setting RSA keygen bits\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }

    // Create and initialize the public exponent.
    bn_e = BN_new();
    if (!bn_e) {
        fprintf(stderr, "[ERROR] Error allocating BIGNUM for exponent\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (BN_set_word(bn_e, e) != 1) {
        fprintf(stderr, "[ERROR] Error setting BIGNUM word for exponent\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    // In OpenSSL 3.0, EVP_PKEY_CTX_set_rsa_keygen_pubexp takes ownership of bn_e.
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, bn_e) <= 0) {
        fprintf(stderr, "[ERROR] Error setting RSA public exponent\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }

    // Avoid double free: set bn_e to nullptr since ownership has been transferred.
    bn_e = nullptr;

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        fprintf(stderr, "[ERROR] Error generating RSA keypair\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }

    // Use temporary buffers for DER encoding.
    {
        unsigned char *tmp_priv = nullptr;
        priv_len = i2d_PrivateKey(pkey, &tmp_priv);
        if (priv_len < 0 || priv_len > ASYM_SIZE) {
            fprintf(stderr, "[ERROR] Error encoding private key or buffer is too small\n");
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
            fprintf(stderr, "[ERROR] Error encoding public key or buffer is too small\n");
            OPENSSL_free(tmp_pub);
            status = CRYPTO_FAILURE;
            goto cleanup;
        }
        memcpy(key_structure->pub_key, tmp_pub, pub_len);
        key_structure->pub_key_len = pub_len;
        OPENSSL_free(tmp_pub);
    }

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
        fprintf(stderr, "[ERROR] Error decoding public key DER\n");
        return CRYPTO_FAILURE;
    }

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        fprintf(stderr, "[ERROR] Error creating context for encryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        fprintf(stderr, "[ERROR] Error initializing encryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "[ERROR] Error setting RSA padding\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    // Determine the required buffer length for encryption.
    if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, message, message_len) <= 0) {
        fprintf(stderr, "[ERROR] Error determining encrypted length\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (outlen > (size_t)ASYM_SIZE) {
        fprintf(stderr, "[ERROR] Encrypted data length exceeds buffer size\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_encrypt(ctx, encrypted, &outlen, message, message_len) <= 0) {
        fprintf(stderr, "[ERROR] Error encrypting message\n");
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
        fprintf(stderr, "[ERROR] Error decoding private key DER\n");
        return CRYPTO_FAILURE;
    }

    ctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (!ctx) {
        fprintf(stderr, "[ERROR] Error creating context for decryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        fprintf(stderr, "[ERROR] Error initializing decryption\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
        fprintf(stderr, "[ERROR] Error setting RSA padding\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    // Determine the required buffer length for decryption.
    if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, encrypted, encrypted_len) <= 0) {
        fprintf(stderr, "[ERROR] Error determining decrypted length\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (outlen > (size_t)ASYM_SIZE) {
        fprintf(stderr, "[ERROR] Decrypted data length exceeds buffer size\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    if (EVP_PKEY_decrypt(ctx, decrypted, &outlen, encrypted, encrypted_len) <= 0) {
        fprintf(stderr, "[ERROR] Error decrypting message\n");
        status = CRYPTO_FAILURE;
        goto cleanup;
    }
    *decrypted_len_out = (int)outlen;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (pkey) EVP_PKEY_free(pkey);
    return status;
}
/*
STATUS decrypt_user_message(int user_id, const unsigned char *encrypted, int encrypted_len, unsigned char *decrypted) {
    priv_key_w_length priv_key_full;
    get_user_private_key(user_id, &priv_key_full);
    int len_out;
    int *ptr = &len_out;
    STATUS decrypt_status = decrypt_with_private_key(priv_key_full.priv_key, priv_key_full.priv_key_len, encrypted, encrypted_len, decrypted, ptr);
    return decrypt_status;
}
*/

/* SYMMETRIC KEYS ---------------------------------------------------*/

STATUS generate_symmetric_key(unsigned char *key, size_t key_size) {
    if (RAND_bytes(key, key_size) != 1) {
        fprintf(stderr, "[ERROR] Error generating symmetric key\n");
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
        fprintf(stderr, "[ERROR] Error creating EVP_CIPHER_CTX\n");
        return SYM_DECRYPT_FAILURE;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "[ERROR] Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_DECRYPT_FAILURE;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, *ciphertext_len) != 1) {
        fprintf(stderr, "[ERROR] Error during decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_DECRYPT_FAILURE;
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        fprintf(stderr, "[ERROR] Error during final decryption (possibly padding issue)\n");
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
        fprintf(stderr, "[ERROR] Error creating EVP_CIPHER_CTX\n");
        return SYM_ENCRYPT_FAILURE;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "[ERROR] Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_ENCRYPT_FAILURE;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, *plaintext_len) != 1) {
        fprintf(stderr, "[ERROR] Error during encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_ENCRYPT_FAILURE;
    }
    *ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        fprintf(stderr, "[ERROR] Error during final encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return SYM_ENCRYPT_FAILURE;
    }
    *ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return SUCCESS;
}


std::string base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    // Create a base64 filter and a memory BIO
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    // Push the base64 filter onto the memory BIO
    bio = BIO_push(b64, bio);
    // Disable newlines in the encoded output
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded;
}

unsigned char* base64_decode(const std::string &encoded, int &out_length) {
    BIO *bio, *b64;
    int decodeLen = encoded.size();
    unsigned char* decoded = new unsigned char[decodeLen];

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int length = BIO_read(bio, decoded, decodeLen);
    BIO_free_all(bio);

    out_length = length;
    return decoded;
}

bool decode_fixed_length(const std::string &encoded, unsigned char* out, size_t expected_size) {
    std::cerr << "[DEBUG] About to Base64‑decode (" << encoded.size()
              << " chars): `" << encoded << "`\n";
    int decodedLength = 0;
    unsigned char* decoded = base64_decode(encoded, decodedLength);
    std::cerr << "[DEBUG] Got encoded token (" << encoded.size()
          << " chars): `" << encoded << "`\n";


    if (decodedLength != static_cast<int>(expected_size)) {
        std::cerr << "[ERROR] Decoded length (" << decodedLength
                  << ") does not match expected (" << expected_size << ")." << std::endl;
        delete[] decoded;
        return false;
    }

    std::memcpy(out, decoded, expected_size);
    delete[] decoded;
    return true;
}


bool decode_fixed_length_sec(const std::string &encoded, unsigned char* out, size_t expected_size) {
    std::string cleaned;
    cleaned.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        char c = encoded[i];
        // turn '\/' → '/'
        if (c == '\\' && i + 1 < encoded.size() && encoded[i+1] == '/') {
            cleaned.push_back('/');
            ++i;  // skip the '/'
        }
        // skip any other backslashes
        else if (c == '\\') {
            continue;
        }
        // skip whitespace (just in case)
        else if (std::isspace(static_cast<unsigned char>(c))) {
            continue;
        }
        else {
            cleaned.push_back(c);
        }
    }

    std::cerr << "[DEBUG] Cleaned Base64 token (" << cleaned.size()
              << " chars): `" << cleaned << "`\n";

    // 2) Decode
    int decodedLength = 0;
    unsigned char* decoded = base64_decode(cleaned, decodedLength);
    if (!decoded) {
        std::cerr << "[ERROR] base64_decode returned null\n";
        return false;
    }

    // 3) Verify length
    if (decodedLength != static_cast<int>(expected_size)) {
        std::cerr << "[ERROR] Decoded length (" << decodedLength
                  << ") does not match expected (" << expected_size << ")\n";
        delete[] decoded;
        return false;
    }

    // 4) Copy out and clean up
    std::memcpy(out, decoded, expected_size);
    delete[] decoded;
    return true;
}



/* compute seed phrase hash ------------------- */

void compute_seed_phrase_hash(std::string seed_phrase, int seed_phrase_size, seed_phrase_hash seed_phrase_hash_) {
    SHA256((const unsigned char*)seed_phrase.c_str(), seed_phrase_size, seed_phrase_hash_);
}

//STATUS constant_time_compare(const token_hash a, const token_hash *b, size_t len);
STATUS constant_time_compare_seed_phrase(const seed_phrase_hash a, const seed_phrase_hash b, size_t len) {
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
STATUS verify_seed_phrase(bastion_username username, const std::string received_seed_phrase) {
    seed_phrase_hash stored_hash;
    seed_phrase_hash computed_hash;
    bastion_username uname_local{};
    memcpy(uname_local, username, sizeof(username));
    std::string uname_local_str(uname_local);
    //need to implement get_token_hash
    if (get_seed_phrase_hash_v2(&uname_local_str, &stored_hash) != SUCCESS) {
        fprintf(stderr, "[ERROR] Failed to retrieve stored token hash for username %d.\n", username);
        return CRYPTO_FAILURE;
    }

    //ERROR HERE DEBUGGING
    std::cout << "[DEBUG] Stored hash:\n";
    print_hex(stored_hash, std::size(stored_hash));
    int seed_phrase_length = received_seed_phrase.size();
    compute_seed_phrase_hash(received_seed_phrase, seed_phrase_length, computed_hash);
    std::cout << "[DEBUG] Computed hash:\n";
    print_hex(computed_hash, std::size(computed_hash));


    if (constant_time_compare(stored_hash, computed_hash, HASH_SIZE) == SUCCESS) {
        printf("[INFO] Token verification succeeded.\n");
        return SUCCESS;
    }

    printf("[INFO] Token verification failed.\n");
    return VERIFICATION_FAILURE;
}

/*
//this shit simulates main to test crypto functions
int test_as_main() {
    sym_key key;
    sym_iv iv;

    if (generate_symmetric_key(key, KEY_SIZE) != SUCCESS) {
        std::fprintf(stderr, "[ERROR] Symmetric key generation failed.\n");
        return -1;
    }

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        std::fprintf(stderr, "[ERROR] IV generation failed.\n");
        return -1;
    }

    asym_key_struct asym_keys{};
    if (generate_asym_keypair(&asym_keys) != SUCCESS) {
        std::cerr << "[ERROR] Failed to generate asymmetric key pair\n";
        return -1;
    }

    priv_key_w_length priv_key_full{};
    memcpy(priv_key_full.priv_key, asym_keys.priv_key, asym_keys.priv_key_len);
    priv_key_full.priv_key_len = asym_keys.priv_key_len;
    STATUS asym_priv_store_stat = store_user_private_key(1, &priv_key_full);

    token auth_token{};
    if (generate_token(auth_token, TOKEN_SIZE) != SUCCESS) {
        std::fprintf(stderr, "[ERROR] Auth token generation failed\n");
        return -1;
    }

    //compute hash of token, store it
    token_hash computed_hash{};
    compute_token_hash(auth_token, TOKEN_SIZE, computed_hash);

    STATUS store_token_hash_stat = store_token_hash(1, computed_hash, TOKEN_SIZE);
    if (store_token_hash_stat != SUCCESS) {
        std::cout << "[ERROR] ERROR STORING HASH, EXITING\n";
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

int test_sym_encode_json() {
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


    std::string encoded_key = base64_encode(key, KEY_SIZE);
    std::cout << "Encoded key:\n" << encoded_key << std::endl;

    /*
    std::vector<unsigned char> decoded_key = base64_decode(encoded_key);
    std::cout << "Decoded binary key:\n";
    for (unsigned char byte : decoded_key) {
        printf("%02x", byte);
    }
    std::cout << std::endl;

    return 0;
}

int test_full_send() {
    /*
     *Here we need to do as follows:
     * Create auth token
     * Create auth token hash
     * Store auth token hash
     * Create asym keys, store the public one in a file and private one in the database
     * Create sym key and store it in a file
     * Encrypt auth token hash with sym key
     * Encrypt sym-encrypted auth token with public key
     * Encode this to a string
     * Encrypt sym ket with public key
     * Encode this to a string
     * Put those encode in the bash test file
     * Send that back as json
     * Decode it all and verify it works




    //Create auth token ----------------------------------------------------------------
    token auth_token{};
    if (generate_token(auth_token, TOKEN_SIZE) != SUCCESS) {
        std::fprintf(stderr, "Auth token generation failed\n");
        return -1;
    }
    std::printf("Auth Token Step 1. This gets sent from mobile as is:\n");
    print_hex(auth_token, TOKEN_SIZE);

    //compute hash of token ----------------------------------------------------------------
    token_hash computed_hash{};
    compute_token_hash(auth_token, TOKEN_SIZE, computed_hash);
    std::printf("Computed Token Hash. This gets stored in DB:\n");
    print_token_hash(computed_hash);

    //Store token hash ---------------------------------------------------------------------
    STATUS store_token_hash_stat = store_token_hash(1, computed_hash, TOKEN_SIZE);
    std::cout << "Store token hash status: " << store_token_hash_stat << "\n";
    if (store_token_hash_stat != SUCCESS) {
        std::cout << "ERROR STORING HASH, EXITING\n";
        return 1;
    }



    //create asym keys ----------------------------------------------------------------------
    asym_key_struct asym_keys{};
    if (generate_asym_keypair(&asym_keys) != SUCCESS) {
        std::cerr << "Failed to generate asymmetric key pair\n";
        return -1;
    }

    std::cout << "PRIVATE KEY LENGTH: " <<asym_keys.priv_key_len << "\n";

    //store private key ----------------------------------------------------------------------
    priv_key_w_length priv_key_full{};
    memcpy(priv_key_full.priv_key, asym_keys.priv_key, asym_keys.priv_key_len);
    priv_key_full.priv_key_len = asym_keys.priv_key_len;
    STATUS asym_priv_store_stat = store_user_private_key(1, &priv_key_full);

    //store public key -----------------------------------------------------------------------
    /*
    std::ofstream pub_key_file = std::ofstream("Cryptography/asym_pub_key.bin", std::ios::binary);
    pub_key_file.write(reinterpret_cast<const char*>(&asym_keys.pub_key), sizeof(asym_keys.pub_key));



    //Generate sym key and iv ------------------------------------------------------------------

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



    //encrypt token with sym key
    int auth_token_size = std::size(auth_token);
    unsigned char sym_encrypted[256] = {0};
    int sym_encrypted_len = 0;
    if (sym_encrypt(auth_token, &auth_token_size,
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
    std::cout << "Asym encrpyted hash length: " << asym_encrypted_hash_len << std::endl;




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
    std::cout <<"Asym enc length: " << asym_encrypted_keyiv_len << std::endl;


    //encode both to strings
    //OLD ERROR WAS IT WAS BEING ENCODED WITH WRONG LENGTH. NOW FIXED
    std::string encoded_key_iv = base64_encode(asym_encrypted_keyiv, asym_encrypted_keyiv_len);
    std::string encoded_token_hash = base64_encode(asym_encrypted_hash, asym_encrypted_hash_len);

    std::cout << "Encoded key iv. This will get sent back by the user:\n" << encoded_key_iv << "\n";
    std::cout << "Encoded token. this will be sent back by the user:\n" << encoded_token_hash << "\n";


    unsigned char decoded_token_hash[asym_encrypted_hash_len];
    unsigned char decoded_key_iv[asym_encrypted_keyiv_len];
    decode_fixed_length(encoded_token_hash, decoded_token_hash, asym_encrypted_hash_len);
    decode_fixed_length(encoded_key_iv, decoded_key_iv, asym_encrypted_keyiv_len);

    std::cout << "Decoded success" << std::endl;

    std::cout << "Decoded token hash:" << std::endl;
    print_hex(decoded_token_hash, asym_encrypted_hash_len);
    std::cout << "Decoded key iv:" << std::endl;
    print_hex(decoded_key_iv, asym_encrypted_keyiv_len);


    return 0;

}

void test_encode_decode() {
    char token_hash_wrapped[] = "4fe2ca3bef2817a03bdf8847981f55ff7942812d61244bb929870d8d27a283aeb2e62ed76c779a946045bb921149bc33be4d7cb24993968cdad642a9e15f1c9227245ce928c36dcbc36a2d904285a5d32fe4c2cdc3c35826ff94dc8dce6b2a2d61b6a4fd622ea18d65470f921fadf3111be9201959cb28fd7d7a1972d0e21d5af9b4ebe86b7f33a5a5bb93c63bd0ba8f792472e9df91d51c39d4a5560c7679955a2c720aa5530666ada980d4a6645a01ab688991121671f1437068d3c884ba564fe2d6bf96b4ff12a8848103c3a0988afa10eb7240920c64208487f6d0c526e0190c5834f51ea604c52ce7977881e130d4769ff94b58bdf7c24f62b3903e7dc9";
    std::string encoded_token_hash = base64_encode((const unsigned char*)token_hash_wrapped, strlen(token_hash_wrapped));

    unsigned char out[512];
    decode_fixed_length(encoded_token_hash, out, strlen(token_hash_wrapped));
    std::cout << "moving to sym_key" << std::endl;

    char sym_key_iv_wrapped[] = "7c6cdef23c45414676a6f1fbe23888713fde8fdea254964b7762ae046f14f3d468903e9f44693e0775d27941c65f9342e2d8c0b9201f7ea458748cf296becded12ddffda28b81b96fe14803ec8247b166a21d9dc412e5fe99d4253f3aa132a2c7b529658be3e1c1af8489471833a2db0beaaf974990754bb5b7c8197eb62147eea21678df7d2fd893d5602809594e41a347757c1f706ec74277da5df6614d3c00205ff7f52a9f96f5afcb62f9a582cb7afd8de968b2f2ff3bad220db2d25d728a18377c102e43cb21c059c21692274514e25d0e565adb71d367dcb6c5ac8dcdf3ac19916ff8d93775a2c2d3ba9ac8b369c885594c1228563a60746323a2570ee";
    std::string encoded_sym_iv = base64_encode((const unsigned char*)sym_key_iv_wrapped, strlen(sym_key_iv_wrapped));
    unsigned char sym_out[513];
    decode_fixed_length(encoded_sym_iv, sym_out, strlen(sym_key_iv_wrapped));
    std::cout << "Finished encoded/decode test" << std::endl;

}

void test_decode() {
    char encoded_token_hash[] = "PwXzx59yEJaF+MFgeAIHG6MLmUFweOUCx+ZXbcu6jbM=";
    char encoded_sym_iv[] = "VYk94ll7mArMpSGFz1K6Ub5jduUujlk0mSqO2iQ4WPhj5hYdXAS87YQ6Ry+yd0v/Llpra9EBT2lx1+dS2XsPcTkWxWuZSZR1EplP7E8YjZ28gPfQs7nvpFvnntDK5FRB7yX8zL497ZCdhIC+qpqNtlZqArubPe6MJtZ1TGnUgk2liggU19Vqyf0jint9Ix4rxEQIBOjLUwWMOAxdLmD2100NOHncZZayprL/g2MSGp8CiDA3ZWTgR+rXN97r8oRGndlUUJ/ymR5S8yGl/WJsjbq5wNMlKy6kjIr9DcUkTjIUlVRXAvykaWXLy45pv9gaI7+/iFGxhb12mSdROTogVA==";

    unsigned char token_hash_out[32];
    unsigned char sym_iv_out[32];

}

*/