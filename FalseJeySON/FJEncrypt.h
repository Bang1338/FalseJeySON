/*
    FalseJeySON 
    Encrypt function

    By bang1338
*/
#ifndef FJENCRYPT_H
#define FJENCRYPT_H

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

// Disable stupid C4996 error
#pragma warning(disable : 4996)

// Disable stupid crypto linker error
#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

// AES256 Key length
#define AES256_KEY_LENGTH 32

// Generate a formatted timestamp string
std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);

    std::ostringstream timestamps;
    timestamps << std::put_time(std::localtime(&t), "%d-%m-%y-%H-%M-%S");
    return timestamps.str();
}
std::string currentTimestamp = GetTimestamp(); // Save to somewhere

// Step 1: 

// Generate AES Key and IV
std::vector<unsigned char> GenerateAES() {
    std::vector<unsigned char> key(AES256_KEY_LENGTH);
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);

    if (RAND_bytes(key.data(), AES256_KEY_LENGTH) != 1) {
        throw std::runtime_error("Error generating AES key");
    }

    if (RAND_bytes(iv.data(), AES_BLOCK_SIZE) != 1) {
        throw std::runtime_error("Error generating IV");
    }

    return key;
}

// Encrypt JSON
std::string EncryptJSON(const std::string& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    EVP_CIPHER_CTX* ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        throw std::runtime_error("Error allocating cipher context");
    }

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data())) {
        throw std::runtime_error("Error initializing encryption");
    }

    std::string encryptedData;
    encryptedData.resize(data.size() + AES_BLOCK_SIZE);

    int encryptedLength = 0;

    // Provide the data to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, (unsigned char*)encryptedData.data(), &encryptedLength, (const unsigned char*)data.data(), data.size())) {
        throw std::runtime_error("Error encrypting data");
    }

    int finalizeLength = 0;

    // Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, (unsigned char*)encryptedData.data() + encryptedLength, &finalizeLength)) {
        throw std::runtime_error("Error finalizing encryption");
    }

    encryptedLength += finalizeLength;
    encryptedData.resize(encryptedLength);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return encryptedData;
}

// Step 2: Create the key.FJKEY file
void MakeBIN(const std::string& header, const std::string& version, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
    std::ofstream file("key_" + currentTimestamp + ".FJKEY", std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening key.FJKEY file");
    }

    // Write the header, version, key, and IV to the file
    file.write(header.c_str(), header.size());
    file.write(version.c_str(), version.size());
    file.write(reinterpret_cast<const char*>(key.data()), key.size());
    file.write(reinterpret_cast<const char*>(iv.data()), iv.size());

    file.close();
}

// Step 3: Encode data to hex
std::string HexEncode(const std::string& input) {
    std::string hexEncoded;
    static const char* hexChars = "0123456789ABCDEF";

    for (char c : input) {
        hexEncoded.push_back(hexChars[(c >> 4) & 0xF]);
        hexEncoded.push_back(hexChars[c & 0xF]);
    }

    return hexEncoded;
}

// Step 4: Encode data to Base64
std::string Base64Encode(const std::string& input) {
    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(b64, bio);

    BIO_write(b64, input.c_str(), input.length());
    BIO_flush(b64);

    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);

    std::string base64Encoded(bptr->data, bptr->length);

    BIO_free_all(b64);

    return base64Encoded;
}

// Step 5: Padding data with {"FJ[version]* and then Base64
std::string Encode(const std::string& data, const std::string& version) {
    std::string encodedData = "{\"FJ" + version + "*" + data;
    return Base64Encode(encodedData);
}

// Encrypt
// TODO: Can (re)use keyfile
void FJEncrypt(const std::string& jsonFileName, std::string& encFileName) {

    std::cout << "FalseJeySON, version 0.1.00" << '\n' << "Encrypt mode" << '\n';
    // Load JSON data from a file
    std::ifstream jsonFile(jsonFileName);
    if (!jsonFile.is_open()) {
        std::cerr << "Error opening JSON file" << '\n';
    }

    auto jFo = nlohmann::ordered_json::parse(jsonFile); // Avoid object keys sorted alphabetically
    std::string jsonData;
    jsonData = jFo.dump(2);

    std::cout << jFo.dump(2) << '\n';

    // Default output file name
    // It should have timestamp in it, otherwise it won't work.
    if (encFileName.empty()) encFileName = "output_" + GetTimestamp() + ".json";    // If output file name contains extension
    else if (encFileName.find('.') != std::string::npos) {
        std::string ext = encFileName.substr(encFileName.find('.'));
        encFileName = encFileName.replace(encFileName.find('.'), ext.size(), "_" + GetTimestamp() + ext);
    }
    else encFileName += "_" + GetTimestamp() + ".json";    // If output file name does not contain extension

    // TODO: JSON compression without object keys sorted alphabetically

    // Step 1: Generate AES Key and IV
    std::vector<unsigned char> aesKey = GenerateAES();
    std::vector<unsigned char> iv = GenerateAES();
    //std::cout << "step 1 done" << '\n'; /* Used while debug, don't ask */

    // Step 2: Create the key.FJKEY file
    std::string header = "FalseJeySON!"; // Header size: 12
    std::string version = "0100"; // Version size: 4 - Version: 0.1.00 - MUST BE 4
    MakeBIN(header, version, aesKey, iv);
    //std::cout << "step 2 done" << '\n';

    // Step 3: Encrypt JSON with AES and encode to Hex
    std::string encryptedData = EncryptJSON(jsonData, aesKey, iv);
    //std::cout << "step 3 enc done" << '\n';

    std::string hexEncodedData = HexEncode(encryptedData);
    //std::cout << "step 3 hexenc done" << '\n';

    // Step 4: Encode data to Base64
    std::string base64EncodedData = Base64Encode(hexEncodedData);
    //std::cout << "step 4 done" << '\n';

    // Step 5: Encode data with {"FJ[version]* and then Base64
    std::string encodedData = Encode(base64EncodedData, version);
    //std::cout << "step 5 done" << '\n';

    // Output the final encoded data to the output file
    std::ofstream outputFile(encFileName);
    if (!outputFile.is_open()) {
        std::cerr << "Error creating output JSON file" << '\n';
    }

    outputFile << encodedData;
    outputFile.close();

    std::cout << "Encryption complete. Encrypted JSON saved to " << encFileName << '\n';
    std::cout << "Key file saved as " << "key_" + currentTimestamp + ".FJKEY" << '\n';
    std::cout << "DO NOT LOSE THE KEYFILE" << '\n';
}

#endif // ENCRYPT_H