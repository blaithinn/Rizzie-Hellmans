#pragma once
#include <string>
#include <vector>
#include <sodium.h>

class CryptoUtils {
public:
    // Key pair generation
    static void generateKeyPair(std::vector<unsigned char>& publicKey,
                                std::vector<unsigned char>& privateKey);

    // Encode/decode base64 for sending keys over HTTP
    static std::string toBase64(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> fromBase64(const std::string& b64);
};
