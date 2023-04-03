
namespace invilite {

class ClientHandler {
public:
    ClientHandler(int client_socket);
    int getSocket() const;

protected:
    int socket;
};

}
