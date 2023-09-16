/*
    FalseJeySON
    Decrypt function

    By bang1338
*/
#ifndef FJDECRYPT_H
#define FJDECRYPT_H

#include <iostream>
#include <sstream>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <nlohmann/json.hpp>

// Disable stupid crypto linker error
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

// AES256 Key length  
#define AES256_KEY_LENGTH 32

std::string Base64Decode(const std::string& input) {
    BIO* bio = BIO_new_mem_buf(input.data(), -1); // No limit on input size
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // No newlines in encoded data
    BIO_push(b64, bio);

    char buffer[1024];
    std::string decoded;
    while (true) {
        int len = BIO_read(b64, buffer, sizeof(buffer));
        if (len <= 0) {
            break;
        }
        decoded.append(buffer, len);
    }

    BIO_free_all(b64);

    return decoded;
}

std::string HexDecode(const std::string& input) {
    std::string decoded;
    for (size_t i = 0; i < input.length(); i += 2) {
        std::string byte = input.substr(i, 2);
        char chr = (char)(int)strtol(byte.c_str(), NULL, 16);
        decoded.push_back(chr);
    }
    return decoded;
}

std::string DecryptAES(const std::string& data,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Error allocating cipher context");
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        throw std::runtime_error("Error initializing decryption");
    }

    std::string decryptedText;
    decryptedText.resize(data.size());

    int decryptedLength = 0;
    if (1 != EVP_DecryptUpdate(ctx, (unsigned char*)decryptedText.data(), &decryptedLength,
        (const unsigned char*)data.data(), data.size())) {
        throw std::runtime_error("Error decrypting data");
    }

    int finalizeLength = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, (unsigned char*)decryptedText.data() + decryptedLength, &finalizeLength)) {
        throw std::runtime_error("Error finalizing decryption");
    }

    decryptedLength += finalizeLength;
    decryptedText.resize(decryptedLength);

    EVP_CIPHER_CTX_free(ctx);

    return decryptedText;
}

std::string PrintHex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex;

    for (unsigned char c : data) {
        ss << std::setfill('0') << std::setw(2) << (int)c;
    }

    return ss.str();
}

std::string FJDecrypt(std::string& encodedFileN, std::string& keyFileN) {
    // Load encoded data
    std::ifstream encodedFile(encodedFileN);
    std::string encodedData;
    encodedFile >> encodedData;

    // Load key 
    std::ifstream keyFile(keyFileN, std::ios::binary);
    if (!keyFile) {
        return "Error opening key file\n";
    }

    // Load key
    /*
        TODO: Read last to first on the keyfile (remember to be flipped after read, or nope)

        46 61 6C 73 65 4A 65 79 53 4F 4E 21 
        ========= Doesn't need it =========

        30 31 30 30
        Read version last

        04 94 98 5B 0B 14 E4 C3 8B 2E 68 EF 2B 04 30 02 41 F8 32 E4 63 5F F0 84 6A AA 8F 0B 15 15 09 B3
                                                     <---------------- Read key second ----------------

        6C D6 93 57 10 B3 77 16 82 29 6B DC 08 A4 F3 04 36 D7 EB 2D 00 1E A4 65 EC 57 9E E3 43 11 BB 11
                                                     <----------------- Read IV first -----------------
    */
    std::string header(12, ' ');
    keyFile.read((char*)header.data(), header.size());

    std::string version(4, ' ');
    keyFile.read((char*)version.data(), version.size());

    std::vector<unsigned char> key(AES256_KEY_LENGTH);
    keyFile.read((char*)key.data(), key.size());

    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    keyFile.read((char*)iv.data(), iv.size());

    // Step 1: Base64 decode the encoded data
    std::string base64Decoded = Base64Decode(encodedData);

    // Step 2: Remove prefix, base64 decode again 
    size_t prefixEnd = base64Decoded.find("*") + 1;
    base64Decoded.erase(0, prefixEnd);
    std::string extracted = Base64Decode(base64Decoded);

    // Step 3: Hex decode
    std::string hexDecoded = HexDecode(extracted);

    // Step 4: Decrypt AES 
    std::string decrypted = DecryptAES(hexDecoded, key, iv);

    // Step 5: Return original data
    /*
        TODO:
        - Return as compressed
        - Return as decompressed
        => No object keys sorted alphabetically
    */
    return decrypted; // You can just use dump, but i found it not too much important
}

#endif // DECRYPT_H
