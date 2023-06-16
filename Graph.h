#ifndef GRAPH_H
#define GRAPH_H

#include <SFML/Graphics.hpp>    // libsfml-dev
#include <vector>
#include <string>
#include <cmath>
#include <unordered_map>

class Graph {
public:
    Graph(const sf::Font &font, const sf::Vector2u &windowSize);
    void addNode(const std::string &id, const std::vector<std::string> &connections);
    void removeNode(const std::string &id);
    void draw(sf::RenderWindow &window);

protected:
    void arrangeNodes();

private:
    struct Node {
        sf::CircleShape circle;
        sf::Text label;
        std::vector<std::string> connections;

        Node() {}
        Node(float radius, const std::string &text, const std::vector<std::string> &conns, const sf::Font &font)
            : circle(radius), label(), connections(conns) {
            label.setFont(font);
            label.setString(text);
            label.setCharacterSize(14);
            label.setFillColor(sf::Color::White);
        }
    };

    std::unordered_map<std::string, Node> nodes;
    sf::Font font;
    sf::Vector2u windowSize;

    void drawArrow(sf::RenderWindow &window, const sf::Vector2f &start, const sf::Vector2f &end, const sf::Color &color, float thickness, float arrowSize, float circleRadius);
};


#endif // GRAPH_H
