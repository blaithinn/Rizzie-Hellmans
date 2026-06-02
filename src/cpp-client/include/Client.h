#pragma once
#include <string>
#include <memory>
#include <vector>
#include "HttpClient.h"
#include "KeyStore.h"
#include "MessageStore.h"

class Client {
public:
    explicit Client(const std::string& serverUrl);

    void setKeyPair(const std::vector<unsigned char>& publicKey,
                    const std::vector<unsigned char>& privateKey);

    bool registerUser(const std::string& username, const std::string& password);
    bool login(const std::string& username, const std::string& password);
    void sendMessage(int recipientUserId, const std::string& plaintext);
    void fetchAndDecryptMessages();
    void deleteMessage(const std::string& messageId);

    bool isLoggedIn() const;
    int  getUserId()  const;

private:
    std::string serverUrl;
    std::unique_ptr<HttpClient>   http;
    std::unique_ptr<MessageStore> store;
    KeyStore keyStore_;

    std::string                token;
    int                        userId = 0;
    std::vector<unsigned char> myPublicKey;
    std::vector<unsigned char> myPrivateKey;
    std::string                publicKeyB64;
};
