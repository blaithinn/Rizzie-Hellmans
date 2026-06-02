#pragma once
#include <string>
#include <memory>
#include <vector>
#include "HttpClient.h"
#include "KeyStore.h"
#include "MessageStore.h"
#include "User.h"

class Client {
public:
    explicit Client(const std::string& serverUrl);

    void setKeyPair(const std::vector<unsigned char>& publicKey,
                    const std::vector<unsigned char>& privateKey);

    bool registerUser(const std::string& username, const std::string& password);
    bool login(const std::string& username, const std::string& password);
    bool changePassword(const std::string& currentPassword, const std::string& newPassword);
    void sendMessage(int recipientUserId, const std::string& plaintext);
    void forwardMessage(const std::string& messageId, int recipientUserId);
    void fetchAndDecryptMessages();
    void downloadMessage(const std::string& messageId);
    void revokeAccess(const std::string& messageId, int targetUserId);
    void deleteMessage(const std::string& messageId);

    bool isLoggedIn() const;
    int  getUserId()  const;

private:
    std::string serverUrl;
    std::unique_ptr<HttpClient>   http;
    std::unique_ptr<MessageStore> store;
    KeyStore                      keyStore_;
    std::unique_ptr<User>         currentUser_;

    std::string                token;
    int                        userId = 0;
    std::vector<unsigned char> myPublicKey;
    std::vector<unsigned char> myPrivateKey;
    std::string                publicKeyB64;
};
