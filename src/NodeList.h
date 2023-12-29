#ifndef NODE_LIST_H
#define NODE_LIST_H

#include <set>
#include <mutex>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include "File.h"

namespace invilite {

class NodeList: public File {
public:
    NodeList(const std::string& filePath);
    bool add(const std::vector<std::string>& addresses);
    bool add(const std::string& address);
    void remove(const std::string& address);
    const std::set<std::string>& getAll() const;

    // Implementing iterators
    using iterator = std::set<std::string>::iterator;
    using const_iterator = std::set<std::string>::const_iterator;

    iterator begin() {
        return list.begin();
    }

    const_iterator begin() const {
        return list.cbegin();
    }

    iterator end() {
        return list.end();
    }

    const_iterator end() const {
        return list.cend();
    }

    // Overloaded global begin() and end() functions for NodeList
    static NodeList::const_iterator begin(const NodeList& nodeList);
    static NodeList::const_iterator end(const NodeList& nodeList);


protected:
    std::set<std::string> list;

private:
    std::mutex list_mutex;
    void parseContent();
    void updateContent();
};

} // namespace invilite

#endif // NODE_LIST_H