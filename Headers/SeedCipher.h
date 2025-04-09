//
// Created by root on 4/8/25.
//

#ifndef SEEDCIPHER_H
#define SEEDCIPHER_H

#include <string>
#include <vector>
#include <bastion_data.h>


//helper functions
std::string toHex(const std::string &input);



class SeedCipher {
public:
    // Nested structure to hold a hardcoded BIP‑39 word list.
    struct WordList {
        std::vector<std::string> words;
        WordList();
    };

    // Constructor: specify the number of words for the seed phrase (default is 12).
    SeedCipher(int numWords = 12);

    // Destructor: clear sensitive data from memory.
    ~SeedCipher();

    // Generate a seed phrase by randomly picking words from the hardcoded word list.
    void generateSeedPhrase();

    // Get the generated seed phrase.
    std::string getSeedPhrase() const;

    // Set the seed phrase manually (useful for restoring a lost account).
    void setSeedPhrase(const std::string &seed);

    // Derive the symmetric key from the seed phrase using PBKDF2 with HMAC‑SHA‑256.
    void deriveKey();

    // Get the derived key as a hexadecimal string.
    std::string getKeyHex() const;

    // Generate a new random Initialization Vector (IV) for encryption.
    void generateIV();

    // Encrypt data (plain text or binary) using AES in CBC mode.
    // The returned string contains the IV prepended to the ciphertext.
    std::string encryptText(const std::string &plainText);

    // Decrypt data (with IV prepended) and return the recovered plaintext (or binary data).
    std::string decryptText(const std::string &cipherWithIV);


    // New functions to work with fixed-size tokens:
    // Encrypt a fixed TOKEN_SIZE bytes token; the output will be exactly 16 + TOKEN_SIZE + 16 bytes.
    void encryptToken(const token plaintext, token_sec &encrypted);

    // Decrypt a fixed-size encrypted token (of token_sec size) and return a TOKEN_SIZE-byte token.
    void decryptToken(const token_sec encrypted, token &plaintext);

private:
    WordList wordList;      // Hardcoded word list for seed generation.
    int numWords;           // Number of words in the seed phrase.
    std::string seedPhrase; // The generated or provided seed phrase.

    // Fixed parameters for deterministic key derivation.
    static constexpr const char* fixedSalt = "FixedSaltValue";
    const int iterations = 10000;
    const size_t keySize = 32;  // 32 bytes for AES-256.

    // Derived symmetric key and the Initialization Vector.
    unsigned char key[32];    // Derived key.
    unsigned char iv[16];     // IV (AES block size: 16 bytes).

    bool keyDerived;          // Indicates if the key has been derived.
};

#endif // SEEDCIPHER_H
