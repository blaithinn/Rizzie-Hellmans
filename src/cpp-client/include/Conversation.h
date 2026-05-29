#pragma once
#include <string>
#include <vector>
#include "Message.h"

class Conversation {
public:
    Conversation(const std::string& participantA, const std::string& participantB);
    void addMessage(const Message& msg);
    const std::vector<Message>& getMessages() const;
private:
    std::string participantA;
    std::string participantB;
    std::vector<Message> messages;
};
