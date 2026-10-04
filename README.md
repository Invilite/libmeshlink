
# Handshake protocol

## 1. Client initiate a handshake
Client generate private and public key "A", public key is sent to server.

### Message content
Message signature is calculated using pre-shared network secret.

| Header   | Public key A | Signature | Random padding |
|----------|--------------|-----------|----------------|
| 24 bytes | 56 bytes     | 32 bytes  | 0 - 255 bytes  |

### Header structure
Last 8 bytes of header are masked using hash from nonce and pre-shared network secret.

| Size     | Name                               |
|----------|------------------------------------|
| 16 bytes | Nonce                              |
| 1 byte   | Handshake protocol version         |
| 1 byte   | Authenticated encryption algorithm |
| 1 byte   | Reserved                           |
| 1 byte   | Reserved                           |
| 1 byte   | Reserved                           |
| 1 byte   | Reserved                           |
| 2 bytes  | CRC16                              |

## 2. Server receive a handshake and sends a reply
Server received public key "A", and generates private and public key "B", 
shared secret is calculated and public key "B" is sent to client in reply.

### Reply content
Reply signature is calculated using pre-shared network secret.

| Header   | Public key B | Signature | Random padding |
|----------|--------------|-----------|----------------|
| 24 bytes | 56 bytes     | 32 bytes  | 0 - 255 bytes  |

### Header structure
Last 8 bytes of header are masked using nonce and pre-shared network secret.

| Size     | Name           |
|----------|----------------|
| 16 bytes | Nonce          |
| 1 byte   | Reserved       |
| 1 byte   | Reserved       |
| 1 byte   | Reserved       |
| 1 byte   | Reserved       |
| 1 byte   | Reserved       |
| 1 byte   | Reserved       |
| 2 bytes  | CRC16          |

## 3. Client receive a reply
Client receive public key "B" and calculate shared secret using previously generated secret.
After that stage all communication is encrypted using shared secret.
