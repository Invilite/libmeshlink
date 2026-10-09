# libmeshlink

The network behind [meshlink](https://github.com/Invilite/meshlink): a C++20 library that turns a program into a node
of an encrypted peer-to-peer mesh. It connects to other nodes over TCP, proves who it is, learns about the rest of the
network from its neighbors and routes messages to every node or to a single one.

Link it if your program should *be* a node. If you only want to send and receive messages through a node that is
already running, you don't need this library: use `meshlink-sdk` from the meshlink repository, or speak the service
protocol yourself.

Status: experimental. The wire format still changes between versions.

## Architecture

```
  Router        broadcast to every node (Plumtree tree), messages to one node (learned routes,
                source routes), acks, route probes, diagnostics          (own thread)
  ----------------------------------------------------------------------------------------
  Network       neighbors and connection limits, peer exchange (PEX), probes of unknown
                nodes, topology, NAT hole punching, the address book    (I/O + management thread)
  ----------------------------------------------------------------------------------------
  Connection    handshake, identity verification, encrypted frames, send queue
  ----------------------------------------------------------------------------------------
  Transport     TcpServer, TcpClient, the platform layer (sockets, poll, thread names)
```

Each layer only talks to the one below it. `PeerDirectory` is the one place where known nodes are kept; Network and
Router share it, and it knows nothing about the protocol.

Threads:

- **I/O thread** (Network): one `poll()` loop for every connection. It reads and decrypts frames, writes queued data and
  calls the listeners. Listeners must only queue work and return: a slow listener stalls every peer.
- **Management thread** (Network): the network's own messages (group `0xFF`), peer exchange, topology, probes, hole
  punching.
- **Router thread**: everything above a single link. It gets events from Network through a queue and calls its own
  listeners (`RouterEventListener`) from this thread.
- **Short-lived workers** for anything that can block: each handshake, each probe, each hole punch attempt.

Sending never blocks. `Connection::send` writes what the socket takes and queues the rest for the I/O thread; a queue
that does not move for too long closes the connection.

## The handshake

Every node of one mesh knows the same 64-byte network key. A connection is set up in two stages.

**Key exchange.** Both messages have the same shape:

| Header | Public key | HMAC | Padding |
|---|---|---|---|
| 24 bytes | 56 bytes (X448) | 32 bytes (HMAC-SHA3-256 with the network key) | 0 to 255 random bytes |

The header is a 16-byte random nonce, the handshake version, the cipher, four reserved bytes and a CRC16. The last 8
bytes of the header are XORed with a mask computed from the nonce and the network key (BLAKE2b), so an observer sees
only random bytes.

1. The client generates an X448 key pair and sends its public key A.
2. The server checks the CRC and the HMAC. A message that fails either check, or comes from someone who does not know
   the network key, is dropped. The server generates its own key pair and sends its public key B in the same format.
3. Both sides compute the X448 shared secret. The session key is derived with HKDF (HMAC-SHA-256), with the server's
   nonce as the salt.

**Identity.** The key exchange only proves that both sides know the network key. Each side then proves its identity
over the encrypted channel:

1. The initiator sends a fresh nonce, a flags byte (for example: this connection is only a reachability probe), its
   Ed25519 and X25519 public keys and its name.
2. The responder answers with the same fields plus an Ed25519 signature over the initiator's nonce and its own fields,
   flags included.
3. The initiator sends its signature over the responder's nonce.

A node's id is BLAKE2b of its two public keys, so an id cannot be claimed without the matching private key.

The identity signatures are not yet bound to the session keys. Someone who knows the network key can sit between two
nodes and relay the identity proof, so treat the network key as a secret shared by people you trust.

## Wire format

Every encrypted frame:

| Nonce | Header | Ciphertext | Tag |
|---|---|---|---|
| 24 bytes | 8 bytes, masked | payload | 16 bytes |

The cipher is XChaCha20-Poly1305 with the session key; the masked header is the associated data. The header holds the
version, a flags byte, the frame length (4 bytes, big-endian) and a CRC16; it is XORed with 8 bytes of BLAKE2b keyed
with the session key over the nonce, so frame lengths are not visible on the wire.

The payload of a frame starts with `group(1) | subtype(2)`. Group `0xFF` is the network's own traffic between two
neighbors and is never forwarded. Groups `0x00` to `0xFD` are messages for applications, `0xFE` is the Router's own.
Routed messages carry this header:

| Field | Size | Note |
|---|---|---|
| version and mode | 1 | version in the high 4 bits; mode: 0 flood, 1 broadcast, 2 routed, 3 unicast |
| flags | 1 | bit 0: ack requested, bit 1: has extensions |
| ttlRemaining, ttlInitial | 1 + 1 | |
| msgId | 8 | unique per sender |
| sentAt | 4 | sender's clock |
| sender | 32 | node id |
| destination | 32 | routed and unicast only |
| route | 1 + 1 + n x 32 | routed only: count, index of the next hop, the hops |
| extensions | 2 + TLV | only with the flag |
| signature | 64 | Ed25519; broadcast and flood, and the Router's own messages |
| payload | rest | |

All integers are big-endian. The fields relays change (`ttlRemaining`, the next hop index, per-hop extensions) are left
out of the signature; everything else is signed.

## Example

`examples/hello_mesh.cpp` is a complete node in about 80 lines:

```cpp
NetworkConfig config;
config.listenPort = *port;
config.nodeName   = "hello-" + std::to_string(*port);

Network network(identity, networkKey, directory, config);
Router  router(network, directory, identity);
router.addListener(std::make_shared<PrintMessages>());

network.start();
router.start();
if (peerPort) network.connectToPeer(peerHost, *peerPort);

while (network.getConnectedPeerCount() == 0) std::this_thread::sleep_for(std::chrono::milliseconds(100));
std::this_thread::sleep_for(std::chrono::milliseconds(500));       // let the other side's Router see us too

const std::string text = "hello from " + config.nodeName;
router.broadcast(16, 1, std::vector<uint8_t>(text.begin(), text.end()));
```

Run two of them:

```bash
make && make examples
./examples/hello_mesh 8420 &
./examples/hello_mesh 8421 127.0.0.1:8420
```

Each prints the other's message. The library logs to standard error.

## Building

On Debian 13 (trixie):

```bash
sudo apt install g++ make pkg-config libbotan-3-dev libgtest-dev
make                         # libmeshlink.a and libmeshlink.so
make test                    # unit and integration tests
make tsan                    # the tests again under ThreadSanitizer
sudo make install            # to /usr/local; PREFIX=... for elsewhere, then pkg-config meshlink
```

Without `libbotan-3-dev`, the build uses the Botan submodule instead: run `git submodule update --init` first, and the
first `make` builds a small static Botan with only the algorithms the library needs. `make BOTAN=bundled` forces that.

`scripts/netns_hole_punch.sh` runs two nodes behind two simulated NATs in Linux network namespaces and checks that hole
punching connects them directly (needs root).

## Code map

| File | Responsibility |
|---|---|
| `TcpServer.cpp`, `TcpClient.cpp` | accepting and opening TCP connections, simultaneous open for hole punching |
| `platform.cpp` | the operating system layer: non-blocking sockets, keepalive, port reuse, `poll`, thread wakeup |
| `connection.cpp` | the handshake, frame encryption and decryption, the send queue |
| `identity_verification.cpp` | the identity proof after the handshake |
| `Identity.cpp` | the node's keys: generate, save, load, sign |
| `signed_peer_record.cpp` | a node's self-signed record: keys, addresses, time |
| `peer.cpp` | one connected neighbor: its connection and state |
| `peer_directory.cpp` | every known node, thread-safe storage with no protocol knowledge |
| `known_peer_eviction.cpp` | which record goes when the address book is full |
| `peer_reachability.cpp` | which of a node's addresses are worth dialing from here |
| `connection_slots.cpp` | hard limits on incoming and outgoing connections |
| `network.cpp` | the Network: I/O and management threads, neighbors, PEX, probes, topology, hole punching |
| `pex_announce.cpp` | peer exchange messages |
| `topology_planner.cpp` | which node to dial next |
| `observed_address.cpp` | the address a neighbor sees us from (detecting NAT) |
| `hole_punch_wire.cpp` | hole punching messages |
| `hole_punch_coordinator.cpp`, `hole_punch_participant.cpp` | the two roles in a hole punch: the node in the middle and the two that connect |
| `hole_punch_policy.cpp` | when a node behind NAT should try a hole punch |
| `log.cpp` | log levels and rate limiting; the application supplies the sink |
| `router_wire.cpp` | routed message encoding, decoding and signatures |
| `routed_message_key.cpp` | the key that identifies one message (sender, msgId) |
| `router.cpp` | the Router: delivery, forwarding, acks, retries, route errors |
| `seen_message_cache.cpp` | duplicate detection |
| `broadcast_cache.cpp` | recent broadcasts, for neighbors that ask for a missing one |
| `plumtree_state.cpp` | the broadcast tree: which links get full copies and which only announcements |
| `tree_root_election.cpp` | choosing one root for the broadcast tree |
| `route_table.cpp` | learned routes to single nodes, ranked by evidence |
| `probe_scheduler.cpp` | which routes to measure, and when |
| `state_report_wire.cpp`, `router_state_report.cpp` | a node's state for diagnostics (`meshlink map`) |

Public headers are in `include/meshlink`; `network.h`, `router.h` and `router_events.h` are where to start.

## License

Apache License 2.0, see [LICENSE](LICENSE). If you ship libmeshlink or code derived from it, keep the [NOTICE](NOTICE)
file with it.
