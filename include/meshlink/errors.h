#pragma once
#include <cstdint>

namespace invilite::Mesh::Error {

enum class Connection : int32_t {
    Success					= 0,
    SocketClosed			= -1,
    SocketError				= -2,
    SocketTimeout			= -3,
    SelectFailed			= -4,	// poll()/select() failed
    ReceivedTooMuch			= -5,	// More data arrived than expected
    LengthMismatch			= -6,	// Received length differs from the expected one
    ChecksumMismatch		= -7,	// Checksum does not match
    SignatureInvalid		= -8,	// HMAC check failed
    UnsupportedProtocol		= -9,
    MissingEncryptionKey	= -10,
    InvalidFrameHeader	    = -11,	// Frame header failed its check
    DecryptionError	        = -12,
    SendQueueFull			= -13,	// No room in the send queue: frame dropped, stream intact; retry later
    MessageTooLarge			= -14,	// Message can never fit a frame or the send queue: dropped, stream intact
};

} // namespace invilite::Mesh::Error