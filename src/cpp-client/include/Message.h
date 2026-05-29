#pragma once
#include <string>

class Message {
public:
    Message(const std::string& id, const std::string& sender,
            const std::string& recipient, const std::string& ciphertext);
    const std::string& getId() const;
    const std::string& getSender() const;
    const std::string& getRecipient() const;
    const std::string& getCiphertext() const;
private:
    std::string id;
    std::string sender;
    std::string recipient;
    std::string ciphertext;
};
