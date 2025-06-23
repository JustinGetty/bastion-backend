#include <iostream>
#include "../Headers/SeedCipher.h"

// Helper function to convert binary data (std::string) to a hex string.

/*
int main() {
    try {
        std::cout << "==== Test 1: Encrypt and Decrypt Text ====" << std::endl;
        // Create an instance of SeedCipher (using 12 words).
        SeedCipher cipher(12);

        // Generate a seed phrase and display it.
        cipher.generateSeedPhrase();
        std::string seed = cipher.getSeedPhrase();
        std::cout << "Generated Seed Phrase: " << seed << std::endl;

        // Derive the symmetric key and display it in hex.
        cipher.deriveKey();
        std::string keyHex = cipher.getKeyHex();
        std::cout << "Derived Key (hex): " << keyHex << std::endl;

        // Define a plaintext message.
        std::string plainText = "This is a sample plaintext message!";
        // Encrypt the plaintext (IV is prepended to the ciphertext).
        std::string encrypted = cipher.encryptText(plainText);
        std::cout << "Encrypted Data (IV + ciphertext, hex): " << toHex(encrypted) << std::endl;

        // Decrypt the encrypted text.
        std::string decrypted = cipher.decryptText(encrypted);
        std::cout << "Recovered Text: " << decrypted << std::endl;

        std::cout << "\n==== Test 2: Simulate Account Recovery (Lost Key) ====" << std::endl;
        // Simulate that the account is lost but the seed phrase is stored.
        // Create a new instance and restore the seed phrase.
        SeedCipher recoveredCipher(12);
        std::cout << "Recovery seed: " << seed << "\n";
        recoveredCipher.setSeedPhrase(seed);
        recoveredCipher.deriveKey();
        std::string recoveredKeyHex = recoveredCipher.getKeyHex();
        std::cout << "Recovered Key (hex): " << recoveredKeyHex << std::endl;
        if (keyHex == recoveredKeyHex)
            std::cout << "Success: Derived key matches the original." << std::endl;
        else
            std::cout << "Error: Derived key does not match!" << std::endl;

        // Optionally, re-decrypt the previously encrypted text.
        std::string recoveredText = recoveredCipher.decryptText(encrypted);
        std::cout << "Recovered Text with restored key: " << recoveredText << std::endl;

        std::cout << "\n==== Test 3: Encrypt and Decrypt Binary Data ====" << std::endl;
        // Simulate binary data (for instance, a raw key) that is not null-terminated text.
        // For demonstration, we create a binary blob.
        std::string binaryData;
        binaryData.push_back(static_cast<char>(0xDE));
        binaryData.push_back(static_cast<char>(0xAD));
        binaryData.push_back(static_cast<char>(0xBE));
        binaryData.push_back(static_cast<char>(0xEF));
        binaryData.append("BinaryDataWith\0InTheMiddle", 25); // including a null byte in the middle

        // Encrypt the binary data.
        std::string encryptedBinary = cipher.encryptText(binaryData);
        std::cout << "Encrypted Binary Data (hex): " << toHex(encryptedBinary) << std::endl;

        // Decrypt the binary data.
        std::string decryptedBinary = cipher.decryptText(encryptedBinary);
        std::cout << "Recovered Binary Data (hex): " << toHex(decryptedBinary) << std::endl;

        // Verify that the decrypted binary data matches the original.
        if (decryptedBinary == binaryData) {
            std::cout << "Success: Binary data matches original." << std::endl;
        } else {
            std::cout << "Error: Binary data does not match." << std::endl;
        }

    } catch (std::exception &ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
*/