#include "TransportCodec.h"

namespace tcpmsg {

namespace {

inline void writeU16LE(uint8_t* dst, uint16_t value) {
    dst[0] = static_cast<uint8_t>(value & 0xFF);
    dst[1] = static_cast<uint8_t>((value >> 8) & 0xFF);
}

inline uint16_t readU16LE(const uint8_t* src) {
    return static_cast<uint16_t>(src[0]) |
           (static_cast<uint16_t>(src[1]) << 8);
}

} // namespace

bool TransportCodec::buildOuterFrame(std::vector<uint8_t>& outFrame,
                                     FrameAccumulator::FrameKind kind,
                                     const uint8_t* payload,
                                     uint16_t payloadLen) {
    if (payloadLen > kFrameMaxPayloadLen) return false;
    if (payloadLen > 0 && payload == nullptr) return false;
    if (kind != FrameAccumulator::FrameKind::Data &&
        kind != FrameAccumulator::FrameKind::Ack) {
        return false;
    }

    outFrame.resize(FrameAccumulator::kHeaderSize + payloadLen);

    outFrame[0] = static_cast<uint8_t>(kind);
    outFrame[1] = 0;
    outFrame[2] = static_cast<uint8_t>(payloadLen & 0xFF);
    outFrame[3] = static_cast<uint8_t>((payloadLen >> 8) & 0xFF);

    for (uint16_t i = 0; i < payloadLen; ++i) {
        outFrame[FrameAccumulator::kHeaderSize + i] = payload[i];
    }

    return true;
}

bool TransportCodec::buildDataFrame(std::vector<uint8_t>& outFrame,
                                    const MACAddress& srcMac,
                                    const MACAddress& dstMac,
                                    uint16_t seq,
                                    const uint8_t* payload,
                                    uint16_t payloadLen) {
    const uint16_t totalLen = static_cast<uint16_t>(kDataHeaderSize + payloadLen);
    if (totalLen > kFrameMaxPayloadLen) return false;
    if (payloadLen > 0 && payload == nullptr) return false;

    std::vector<uint8_t> dataPayload(totalLen);

    for (int i = 0; i < 6; ++i) dataPayload[i]     = srcMac.bytes()[i];
    for (int i = 0; i < 6; ++i) dataPayload[6 + i] = dstMac.bytes()[i];

    writeU16LE(&dataPayload[12], seq);

    for (uint16_t i = 0; i < payloadLen; ++i) {
        dataPayload[kDataHeaderSize + i] = payload[i];
    }

    return buildOuterFrame(outFrame,
                           FrameAccumulator::FrameKind::Data,
                           dataPayload.data(),
                           totalLen);
}

bool TransportCodec::buildAckFrame(std::vector<uint8_t>& outFrame,
                                   uint16_t seq,
                                   AckCode code,
                                   uint8_t flags) {
    uint8_t ackPayload[kAckPayloadSize];
    writeU16LE(&ackPayload[0], seq);
    ackPayload[2] = static_cast<uint8_t>(code);
    ackPayload[3] = flags;

    return buildOuterFrame(outFrame,
                           FrameAccumulator::FrameKind::Ack,
                           ackPayload,
                           kAckPayloadSize);
}

bool TransportCodec::parseDataPayload(const uint8_t* payload,
                                      uint16_t payloadLen,
                                      ParsedDataPayload& out) {
    if (payload == nullptr) return false;
    if (payloadLen < kDataHeaderSize) return false;

    for (int i = 0; i < 6; ++i) out.srcMac.bytes()[i] = payload[i];
    for (int i = 0; i < 6; ++i) out.dstMac.bytes()[i] = payload[6 + i];

    out.seq = readU16LE(&payload[12]);
    out.payloadLen = static_cast<uint16_t>(payloadLen - kDataHeaderSize);
    out.payload = (out.payloadLen > 0) ? (payload + kDataHeaderSize) : nullptr;

    return true;
}

bool TransportCodec::parseAckPayload(const uint8_t* payload,
                                     uint16_t payloadLen,
                                     ParsedAckPayload& out) {
    if (payload == nullptr) return false;
    if (payloadLen != kAckPayloadSize) return false;

    out.seq = readU16LE(&payload[0]);
    out.code = static_cast<AckCode>(payload[2]);
    out.flags = payload[3];

    switch (out.code) {
        case AckCode::Ok:
        case AckCode::WrongDestination:
        case AckCode::QueueFull:
        case AckCode::TransportError:
            return true;
        default:
            return false;
    }
}

} // namespace tcpmsg