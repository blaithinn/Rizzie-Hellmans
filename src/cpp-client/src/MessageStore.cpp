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
    auto it = std::find_if(messages.begin(), messages.end(),
        [&id](const Message& m) { return m.getId() == id; });
    return it != messages.end() ? &(*it) : nullptr;
}
