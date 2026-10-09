#include "meshlink/hole_punch_wire.h"

#include <arpa/inet.h>
#include <algorithm>

namespace invilite::Mesh {

std::string_view holePunchDeclineReasonName(const HolePunchDeclineReason reason) {
    switch (reason) {
        case HolePunchDeclineReason::NoSlot:           return "no slot";
        case HolePunchDeclineReason::AlreadyConnected: return "already connected";
        case HolePunchDeclineReason::Busy:             return "busy";
        case HolePunchDeclineReason::TooManyAttempts:  return "too many attempts";
        case HolePunchDeclineReason::NotNeighbor:      return "not a neighbor";
        case HolePunchDeclineReason::RateLimited:      return "rate limited";
        case HolePunchDeclineReason::PeerLeft:         return "peer left";
        case HolePunchDeclineReason::NotAllowed:       return "not allowed";
        case HolePunchDeclineReason::SameNetwork:      return "same network";
    }
    return "unknown";
}

namespace HolePunchCodec {

namespace {
    constexpr uint8_t FAMILY_IPV4 = 4;
    constexpr uint8_t FAMILY_IPV6 = 6;

    // Reads the payload front to back; any read past the end marks the whole decode failed
    class PayloadReader {
    public:
        explicit PayloadReader(std::span<const uint8_t> payload) : payload(payload) {}

        template <size_t N> std::array<uint8_t, N> bytes() {
            std::array<uint8_t, N> out{};
            if (!this->take(N)) return out;
            std::copy_n(this->payload.data() + this->offset - N, N, out.begin());
            return out;
        }
        uint8_t byte() { return this->take(1) ? this->payload[this->offset - 1] : 0; }
        uint16_t uint16() { return this->take(2) ? static_cast<uint16_t>(this->payload[this->offset - 2] << 8 | this->payload[this->offset - 1]) : 0; }

        std::optional<HolePunchEndpoint> endpoint() {
            const uint8_t family = this->byte();
            const size_t  length = family == FAMILY_IPV4 ? 4 : family == FAMILY_IPV6 ? 16 : 0;
            if (length == 0 || !this->take(length)) return std::nullopt;
            char text[INET6_ADDRSTRLEN];
            if (!inet_ntop(family == FAMILY_IPV4 ? AF_INET : AF_INET6, this->payload.data() + this->offset - length, text, sizeof(text))) return std::nullopt;
            HolePunchEndpoint result{ text, 0 };
            result.port = this->uint16();
            return result;
        }

        [[nodiscard]] bool complete() const { return this->ok && this->offset == this->payload.size(); }

    private:
        bool take(size_t count) {
            if (!this->ok || this->payload.size() - this->offset < count) { this->ok = false; return false; }
            this->offset += count;
            return true;
        }

        std::span<const uint8_t> payload;
        size_t                   offset = 0;
        bool                     ok     = true;
    };

    // False when `endpoint.address` is not a numeric IP
    bool appendEndpoint(std::vector<uint8_t>& out, const HolePunchEndpoint& endpoint) {
        uint8_t bytes[16];
        if (inet_pton(AF_INET, endpoint.address.c_str(), bytes) == 1) {
            out.push_back(FAMILY_IPV4);
            out.insert(out.end(), bytes, bytes + 4);
        } else if (inet_pton(AF_INET6, endpoint.address.c_str(), bytes) == 1) {
            out.push_back(FAMILY_IPV6);
            out.insert(out.end(), bytes, bytes + 16);
        } else {
            return false;
        }
        out.push_back(static_cast<uint8_t>(endpoint.port >> 8));
        out.push_back(static_cast<uint8_t>(endpoint.port & 0xFF));
        return true;
    }

    bool isKnownReason(uint8_t value) {
        return value >= static_cast<uint8_t>(HolePunchDeclineReason::NoSlot) && value <= static_cast<uint8_t>(HolePunchDeclineReason::SameNetwork);
    }
}

namespace {
    std::vector<uint8_t> payloadOf(const HolePunchRequest& request) {
        std::vector<uint8_t> out(request.target.begin(), request.target.end());
        out.insert(out.end(), request.nonce.begin(), request.nonce.end());
        return out;
    }

    std::vector<uint8_t> payloadOf(const HolePunchOffer& offer) {
        std::vector<uint8_t> out(offer.initiator.begin(), offer.initiator.end());
        out.insert(out.end(), offer.nonce.begin(), offer.nonce.end());
        if (!appendEndpoint(out, offer.initiatorEndpoint)) return {};
        return out;
    }

    std::vector<uint8_t> payloadOf(const HolePunchAccept& accept) {
        return { accept.nonce.begin(), accept.nonce.end() };
    }

    std::vector<uint8_t> payloadOf(const HolePunchDecline& decline) {
        std::vector<uint8_t> out(decline.nonce.begin(), decline.nonce.end());
        out.push_back(static_cast<uint8_t>(decline.reason));
        return out;
    }

    std::vector<uint8_t> payloadOf(const HolePunchNow& now) {
        std::vector<uint8_t> out(now.nonce.begin(), now.nonce.end());
        if (!appendEndpoint(out, now.remoteEndpoint)) return {};
        return out;
    }

    uint16_t subtypeOf(const HolePunchRequest&) { return HolePunchSubtype::REQUEST; }
    uint16_t subtypeOf(const HolePunchOffer&)   { return HolePunchSubtype::OFFER; }
    uint16_t subtypeOf(const HolePunchAccept&)  { return HolePunchSubtype::ACCEPT; }
    uint16_t subtypeOf(const HolePunchDecline&) { return HolePunchSubtype::DECLINE; }
    uint16_t subtypeOf(const HolePunchNow&)     { return HolePunchSubtype::NOW; }

    std::optional<HolePunchBody> decodeBody(uint16_t subtype, PayloadReader& reader) {
        switch (subtype) {
            case HolePunchSubtype::REQUEST: {
                HolePunchRequest request;
                request.target = reader.bytes<32>();
                request.nonce  = reader.bytes<16>();
                return request;
            }
            case HolePunchSubtype::OFFER: {
                HolePunchOffer offer;
                offer.initiator = reader.bytes<32>();
                offer.nonce     = reader.bytes<16>();
                const auto endpoint = reader.endpoint();
                if (!endpoint) return std::nullopt;
                offer.initiatorEndpoint = *endpoint;
                return offer;
            }
            case HolePunchSubtype::ACCEPT:
                return HolePunchAccept{ reader.bytes<16>() };
            case HolePunchSubtype::DECLINE: {
                HolePunchDecline decline;
                decline.nonce = reader.bytes<16>();
                const uint8_t reason = reader.byte();
                if (!isKnownReason(reason)) return std::nullopt;
                decline.reason = static_cast<HolePunchDeclineReason>(reason);
                return decline;
            }
            case HolePunchSubtype::NOW: {
                HolePunchNow now;
                now.nonce = reader.bytes<16>();
                const auto endpoint = reader.endpoint();
                if (!endpoint) return std::nullopt;
                now.remoteEndpoint = *endpoint;
                return now;
            }
            default:
                return std::nullopt;
        }
    }
}

Encoded encode(const HolePunchBody& body) {
    return std::visit([](const auto& message) { return Encoded{ subtypeOf(message), payloadOf(message) }; }, body);
}

std::optional<HolePunchBody> decode(const uint16_t subtype, std::span<const uint8_t> payload) {
    PayloadReader reader(payload);
    auto body = decodeBody(subtype, reader);
    if (!body || !reader.complete()) return std::nullopt;
    return body;
}

} // namespace HolePunchCodec

} // namespace invilite::Mesh
