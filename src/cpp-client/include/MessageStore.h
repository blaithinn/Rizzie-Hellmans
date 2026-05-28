#pragma once
#include <vector>
#include <unordered_map>
#include "Message.h"

class MessageStore {
public:
    void addMessage(const Message& msg);
    const std::vector<Message>& getAllMessages() const;
    const Message* findById(const std::string& id) const;
private:
    std::vector<Message> messages;
    std::unordered_map<std::string, std::size_t> indexById;
};
