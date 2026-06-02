#include "Conversation.h"

Conversation::Conversation(const std::string& participantA, const std::string& participantB)
    : participantA(participantA), participantB(participantB) {}

void Conversation::addMessage(const Message& msg) {
    messages.push_back(msg);
}

const std::vector<Message>& Conversation::getMessages() const {
    return messages;
}
