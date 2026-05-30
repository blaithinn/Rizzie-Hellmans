#include <iostream>
#include "HttpClient.h"
#include "CryptoUtils.h"

int main() {
    std::cout << "SecureChat C++ Client v0.1" << std::endl;

    // Test key pair generation
    std::vector<unsigned char> publicKey, privateKey;
    CryptoUtils::generateKeyPair(publicKey, privateKey);

    std::string pubKeyB64 = CryptoUtils::toBase64(publicKey);
    std::cout << "Generated public key (base64): " << pubKeyB64 << std::endl;
    std::cout << "Key pair generation successful!" << std::endl;

    return 0;
}
