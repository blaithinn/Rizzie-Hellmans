#pragma once
#include <string>
#include <memory>
#include <vector>
#include "HttpClient.h"

class Client {
public:
    explicit Client(const std::string& serverUrl);
    void fetchAndDecryptMessages(const std::vector<unsigned char>& myPrivateKey,
                                 const std::string& token);
private:
    std::string serverUrl;
    std::unique_ptr<HttpClient> http;
};
