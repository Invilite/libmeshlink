#ifndef NODE_LIST_H
#define NODE_LIST_H

#include <set>
#include <mutex>
#include "File.h"
#include "Node.h"

namespace invilite {

class NodeList: public File {
public:
    NodeList(const std::string& filePath);
    bool add(const std::vector<Node>& nodes);
    bool add(const Node& node);
    void remove(const Node& node);
    const std::set<Node>& getAll() const;

    // Implementing iterators
    using iterator = std::set<Node>::iterator;
    using const_iterator = std::set<Node>::const_iterator;

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
    std::set<Node> list;

private:
    std::mutex list_mutex;
    void parseContent();
    void updateContent();
};

} // namespace invilite

#endif // NODE_LIST_H