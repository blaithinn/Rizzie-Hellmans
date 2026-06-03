#include "MessageStore.h"
#include <algorithm>

void MessageStore::addMessage(const Message& msg) {
    indexById[msg.getId()] = messages.size();
    messages.push_back(msg);
}

const std::vector<Message>& MessageStore::getAllMessages() const {
    return messages;
}

const Message* MessageStore::findById(const std::string& id) const {
    auto it = indexById.find(id);
    if (it == indexById.end()) return nullptr;
    return &messages[it->second];
}
