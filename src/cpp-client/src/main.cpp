#include <iostream>
#include <vector>
#include "Client.h"
#include "CryptoUtils.h"

int main() {
    // TODO 2.8: load key pair from persistent local storage instead of generating fresh each run.
    std::vector<unsigned char> myPublicKey, myPrivateKey;
    CryptoUtils::generateKeyPair(myPublicKey, myPrivateKey);
    std::cout << "Local pubkey (base64): " << CryptoUtils::toBase64(myPublicKey) << "\n\n";

    // TODO 2.10: obtain token via login instead of hardcoding.
    const std::string token = "PASTE_JWT_HERE";

    Client client("https://rizzie-hellmans.theburkenator.com/api/v1");
    client.fetchAndDecryptMessages(myPrivateKey, token);

    return 0;
}
