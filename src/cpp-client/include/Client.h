#pragma once
#include <string>
#include <memory>
#include "HttpClient.h"
#include "MessageStore.h"

class Client {
public:
    Client(const std::string& serverUrl);
    bool login(const std::string& username, const std::string& password);
    bool registerUser(const std::string& username, const std::string& password);
    bool sendMessage(const std::string& recipient, const std::string& plaintext);
    void fetchMessages();
private:
    std::string serverUrl;
    std::string jwtToken;
    std::unique_ptr<HttpClient> http;
    std::unique_ptr<MessageStore> store;
};
