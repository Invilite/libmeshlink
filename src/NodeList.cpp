#include "NodeList.h"

invilite::NodeList::NodeList(const std::string& filePath) : File(filePath) {
    // Load client addresses from file
    read();
    parseContent();
}

// Add a single client address or a vector of addresses to the list and update the content of the file
bool invilite::NodeList::add(const std::vector<Node>& nodes) {
    bool fileUpdated = false;
    std::lock_guard<std::mutex> lock(list_mutex);
    for (const auto& node : nodes) {
        if (list.insert(node).second) {
            fileUpdated = true;
        }
    }

    if (fileUpdated) {
        updateContent();
    }

    return fileUpdated;
}

// Add client address to the list and update the content of the files
bool invilite::NodeList::add(const Node& node) {
    return add(std::vector<Node>{node});
}

// Remove client address from the list and update the content of the file
void invilite::NodeList::remove(const Node& node) {
    std::lock_guard<std::mutex> lock(list_mutex);
    if (list.erase(node) > 0) {
        updateContent();
    }
}

const std::set<Node>& invilite::NodeList::getAll() const {
    return list;
}

void invilite::NodeList::parseContent() {
    std::istringstream iss(getContentAsString());
    std::string line;
    while (std::getline(iss, line)) {
        std::istringstream lineStream(line);
        Node node;
        lineStream >> node.address;
        lineStream >> node.port;
        list.insert(node);
    }
}

void invilite::NodeList::updateContent() {
    std::ostringstream oss;
    for (const auto& node: list) {
        oss << node.address << " " << node.port << std::endl;
    }
    this->setContent(oss.str());
    write();
}

// Implementation of global begin() and end() functions for NodeList
invilite::NodeList::const_iterator invilite::NodeList::begin(const NodeList& nodeList) {
    return nodeList.begin();
}

invilite::NodeList::const_iterator invilite::NodeList::end(const NodeList& nodeList) {
    return nodeList.end();
}
