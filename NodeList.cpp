#include "NodeList.h"


invilite::NodeList::NodeList(const std::string& filePath) : File(filePath) {
    // Load client addresses from file
    read();
    parseContent();
}

// Add a single client address or a vector of addresses to the list and update the content of the file
void invilite::NodeList::add(const std::vector<std::string>& addresses) {
    bool fileUpdated = false;
    for (const auto& address : addresses) {
        if (list.insert(address).second) {
            fileUpdated = true;
        }
    }

    if (fileUpdated) {
        updateContent();
    }
}

// Add client address to the list and update the content of the file
void invilite::NodeList::add(const std::string& address) {
    std::vector<std::string> addresses{address};
    add(addresses);
}

// Remove client address from the list and update the content of the file
void invilite::NodeList::remove(const std::string& address) {
    if (list.erase(address) > 0) {
        updateContent();
    }
}

const std::set<std::string>& invilite::NodeList::getAll() const {
    return list;
}

void invilite::NodeList::parseContent() {
    std::istringstream iss(content());
    std::string line;
    while (std::getline(iss, line)) {
        list.insert(line);
    }
}

void invilite::NodeList::updateContent() {
    std::ostringstream oss;
    for (const auto& address: list) {
        oss << address << std::endl;
    }
    content(oss.str());
    write();
}

// Implementation of global begin() and end() functions for NodeList
invilite::NodeList::const_iterator invilite::NodeList::begin(const NodeList& nodeList) {
    return nodeList.begin();
}

invilite::NodeList::const_iterator invilite::NodeList::end(const NodeList& nodeList) {
    return nodeList.end();
}
