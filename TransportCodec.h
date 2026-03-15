#pragma once

#include <cstdint>
#include <vector>

#include "MACAddress.h"
#include "FrameAccumulator.h"

namespace tcpmsg {

class TransportCodec {
public:
    enum class AckCode : uint8_t {
        Ok               = 0,
        WrongDestination = 1,
        QueueFull        = 2,
        TransportError   = 3
    };

    struct ParsedDataPayload {
        MACAddress srcMac;
        MACAddress dstMac;
        uint16_t seq = 0;
        const uint8_t* payload = nullptr;
        uint16_t payloadLen = 0;
    };

    struct ParsedAckPayload {
        uint16_t seq = 0;
        AckCode code = AckCode::TransportError;
        uint8_t flags = 0;
    };

    static constexpr uint16_t kDataHeaderSize = 6 + 6 + 2;
    static constexpr uint16_t kAckPayloadSize = 2 + 1 + 1;

    static bool buildDataFrame(std::vector<uint8_t>& outFrame,
                               const MACAddress& srcMac,
                               const MACAddress& dstMac,
                               uint16_t seq,
                               const uint8_t* payload,
                               uint16_t payloadLen);

    static bool buildAckFrame(std::vector<uint8_t>& outFrame,
                              uint16_t seq,
                              AckCode code,
                              uint8_t flags = 0);

    static bool parseDataPayload(const uint8_t* payload,
                                 uint16_t payloadLen,
                                 ParsedDataPayload& out);

    static bool parseAckPayload(const uint8_t* payload,
                                uint16_t payloadLen,
                                ParsedAckPayload& out);

private:
    static bool buildOuterFrame(std::vector<uint8_t>& outFrame,
                                FrameAccumulator::FrameKind kind,
                                const uint8_t* payload,
                                uint16_t payloadLen);
};

} // namespace tcpmsg