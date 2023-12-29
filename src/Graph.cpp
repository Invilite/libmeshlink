// #include "Graph.h"

// Graph::Graph(const sf::Font &font, const sf::Vector2u &windowSize): font(font), windowSize(windowSize) {}


// void Graph::addNode(const std::string &id, const std::vector<std::string> &connections) {
//     if (nodes.count(id) == 0) {
//         nodes[id] = Node(20.0f, "Node " + id, connections, font);
//     } else {
//         for (const auto &conn : connections) {
//             nodes[id].connections.push_back(conn);
//         }
//     }

//     arrangeNodes();
// }

// void Graph::removeNode(const std::string &id) {
//     auto it = nodes.find(id);
//     if (it != nodes.end()) {
//         nodes.erase(it);
//     }

//     // Usuń połączenia do usuwanego węzła
//     for (auto &node : nodes) {
//         node.second.connections.erase(std::remove(node.second.connections.begin(), node.second.connections.end(), id), node.second.connections.end());
//     }

//     arrangeNodes();
// }

// void Graph::draw(sf::RenderWindow &window) {
//     for (const auto &node : nodes) {
//         window.draw(node.second.circle);
//         window.draw(node.second.label);
//     }

//     for (const auto &node : nodes) {
//         for (const auto &connection : node.second.connections) {
//             if (nodes.count(connection) > 0) {
//                 sf::Vector2f src = node.second.circle.getPosition() + sf::Vector2f(node.second.circle.getRadius(), node.second.circle.getRadius());
//                 sf::Vector2f dest = nodes[connection].circle.getPosition() + sf::Vector2f(nodes[connection].circle.getRadius(), nodes[connection].circle.getRadius());

//                 drawArrow(window, src, dest, sf::Color::White, 2.0f, 10.0f, node.second.circle.getRadius());
//             }
//         }
//     }
// }

// void Graph::arrangeNodes() {
//     size_t nodeCount = nodes.size();
//     float angleStep = 360.0f / nodeCount;
//     float centerX = windowSize.x / 2.0f;
//     float centerY = windowSize.y / 2.0f;
//     float radius = 200.0f;

//     size_t i = 0;
//     for (auto &node : nodes) {
//         float angle = angleStep * i * 3.14159f / 180.0f;
//         float x = centerX + radius * cos(angle) - node.second.circle.getRadius();
//         float y = centerY + radius * sin(angle) - node.second.circle.getRadius();
//         node.second.circle.setFillColor(sf::Color::White);
//         node.second.circle.setPosition(x, y);
//         node.second.label.setPosition(x, y + 2 * node.second.circle.getRadius());
//         ++i;
//     }
// }

// void Graph::drawArrow(sf::RenderWindow &window, const sf::Vector2f &start, const sf::Vector2f &end, const sf::Color &color, float thickness, float arrowSize, float circleRadius) {
//     sf::Vector2f direction = end - start;
//     float length = std::sqrt(direction.x * direction.x + direction.y * direction.y);
//     direction /= length;

//     sf::Vector2f normal(-direction.y, direction.x);
//     sf::VertexArray vertices(sf::TrianglesStrip, 6);
//     vertices[0].position = start + normal * thickness;
//     vertices[1].position = start - normal * thickness;
//     vertices[2].position = end - direction * arrowSize - direction * circleRadius + normal * thickness;
//     vertices[3].position = end - direction * arrowSize - direction * circleRadius - normal * thickness;
//     vertices[4].position = end - direction * arrowSize + normal * (arrowSize / 2.0f) - direction * circleRadius;
//     vertices[5].position = end - direction * arrowSize - normal * (arrowSize / 5.0f) - direction * circleRadius;

//     for (int i = 0; i < 6; ++i) {
//         vertices[i].color = color;
//     }

//     window.draw(vertices);

//     sf::ConvexShape arrowHead;
//     arrowHead.setPointCount(3);
//     arrowHead.setPoint(0, end - direction * circleRadius);
//     arrowHead.setPoint(1, end - direction * arrowSize + normal * (arrowSize / 2.0f) - direction * circleRadius);
//     arrowHead.setPoint(2, end - direction * arrowSize - normal * (arrowSize / 2.0f) - direction * circleRadius);
//     arrowHead.setFillColor(color);

//     window.draw(arrowHead);
// }

