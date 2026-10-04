#pragma once
#include <cstdint>

namespace invilite::Mesh::Error {

enum class Connection : int32_t {
    Success					= 0,	// Operation completed successfully
    SocketClosed			= -1,	// Socket has been closed
    SocketError				= -2,	// General socket error
    SocketTimeout			= -3,	// Timeout while waiting for data
    SelectFailed			= -4,	// Error returned from select()
    ReceivedTooMuch			= -5,	// Received more data than expected
    LengthMismatch			= -6,	// Received length does not match expected
    ChecksumMismatch		= -7,	// CRC/checksum value is incorrect
    SignatureInvalid		= -8,	// HMAC signature is invalid
    UnsupportedProtocol		= -9,	// Requested protocol is not supported
    MissingEncryptionKey	= -10,	// Missing session encryption key
    InvalidFrameHeader	    = -11,	// Frame header has invalid CRC
    DecryptionError	        = -12,
};

} // namespace invilite::Mesh::Error