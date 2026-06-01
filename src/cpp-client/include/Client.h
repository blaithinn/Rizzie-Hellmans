#pragma once
#include <memory>
#include <string>
#include <vector>
#include "HttpClient.h"
#include "KeyStore.h"

class Client {
public:
    explicit Client(const std::string& serverUrl);

    void sendMessage(int recipientUserId, const std::string& plaintext,
                     const std::vector<unsigned char>& myPrivateKey,
                     const std::string& token);

    void fetchAndDecryptMessages(const std::vector<unsigned char>& myPrivateKey,
                                 const std::string& token);

private:
    std::string serverUrl;
    std::unique_ptr<HttpClient> http;
    KeyStore keyStore_;
};
