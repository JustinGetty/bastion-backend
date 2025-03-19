#!/usr/bin/env bats

# Test constants
SYM_KEY_SIZE=32  # AES-256 requires a 256-bit key (32 bytes)
SYM_IV_SIZE=16   # AES CBC mode requires a 16-byte IV
ASYM_KEY_SIZE=2048
PLAINTEXT="ahhhhhh oh my god"
TOKEN_SIZE=32
ID=1

# Test helpers
generate_symmetric_key() {
    ./cryptotest generate_symmetric_key
}

generate_rsa_keypair() {
    ./cryptotest generate_asym_keypair
}

encrypt_symmetric() {
    ./cryptotest sym_encrypt "$PLAINTEXT"
}

decrypt_symmetric() {
    ./cryptotest sym_decrypt "$1"
}

encrypt_rsa() {
    ./cryptotest encrypt_with_pub_key "$1"
}

decrypt_rsa() {
    ./cryptotest decrypt_with_private_key "$1"
}

# Symmetric key encryption/decryption test
@test "Generate symmetric key" {
    result=$(generate_symmetric_key)
    [[ "$result" == "SUCCESS" ]]
}

@test "Symmetric encryption and decryption" {
    result=$(generate_symmetric_key)
    [[ "$result" == "SUCCESS" ]]

    encrypted=$(encrypt_symmetric "$PLAINTEXT")
    decrypted=$(decrypt_symmetric "$encrypted")

    [[ "$decrypted" == "$PLAINTEXT" ]]
}

# RSA key pair generation test
@test "Generate RSA key pair" {
    result=$(generate_rsa_keypair)
    [[ "$result" == "SUCCESS" ]]
}

@test "RSA encryption and decryption" {
    result=$(generate_rsa_keypair)
    [[ "$result" == "SUCCESS" ]]

    public_key="public_key_der_blob"
    encrypted=$(encrypt_rsa "$public_key" "$PLAINTEXT")
    decrypted=$(decrypt_rsa "$encrypted")

    [[ "$decrypted" == "$PLAINTEXT" ]]
}

# Token verification test
@test "Verify token" {
    result=$(generate_token "$ID" "$TOKEN_SIZE")
    [[ "$result" == "SUCCESS" ]]

    token_hash=$(compute_token_hash "$ID" "$TOKEN_SIZE")
    verification_result=$(verify_token "$ID" "$token_hash")

    [[ "$verification_result" == "SUCCESS" ]]
}

# Full encryption and decryption test flow
@test "Full encryption and decryption process" {
    result=$(generate_symmetric_key)
    [[ "$result" == "SUCCESS" ]]

    encrypted=$(encrypt_symmetric "$PLAINTEXT")
    decrypted=$(decrypt_symmetric "$encrypted")

    [[ "$decrypted" == "$PLAINTEXT" ]]
}

