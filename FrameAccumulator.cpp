#include "FrameAccumulator.h"

namespace tcpmsg {

void FrameAccumulator::reset() {
    header_[0] = 0;
    header_[1] = 0;
    header_[2] = 0;
    header_[3] = 0;
    headerBytes_ = 0;
    payloadBytes_ = 0;
    payload_.clear();
    state_ = State::ReadingHeader;
}

FrameAccumulator::FrameKind FrameAccumulator::decodeFrameKind(uint8_t raw) {
    switch (raw) {
        case static_cast<uint8_t>(FrameKind::Data): return FrameKind::Data;
        case static_cast<uint8_t>(FrameKind::Ack):  return FrameKind::Ack;
        default:                                    return FrameKind::Invalid;
    }
}

bool FrameAccumulator::feed(uint8_t byte) {
    if (state_ == State::Complete || state_ == State::Invalid) {
        return false;
    }

    if (state_ == State::ReadingHeader) {
        header_[headerBytes_++] = byte;

        if (headerBytes_ < kHeaderSize) {
            return false;
        }

        if (decodeFrameKind(header_[0]) == FrameKind::Invalid) {
            state_ = State::Invalid;
            return false;
        }

        const uint16_t len =
            static_cast<uint16_t>(header_[2]) |
            (static_cast<uint16_t>(header_[3]) << 8);

        if (len > kFrameMaxPayloadLen) {
            state_ = State::Invalid;
            return false;
        }

        payload_.resize(len);
        payloadBytes_ = 0;

        if (len == 0) {
            state_ = State::Complete;
            return true;
        }

        state_ = State::ReadingPayload;
        return false;
    }

    // ReadingPayload
    payload_[payloadBytes_++] = byte;

    if (payloadBytes_ >= payload_.size()) {
        state_ = State::Complete;
        return true;
    }

    return false;
}

FrameAccumulator::FrameKind FrameAccumulator::frameKind() const {
    if (!complete()) {
        return FrameKind::Invalid;
    }
    return decodeFrameKind(header_[0]);
}

uint16_t FrameAccumulator::payloadLen() const {
    if (!complete()) {
        return 0;
    }
    return static_cast<uint16_t>(payload_.size());
}

const uint8_t* FrameAccumulator::payload() const {
    if (!complete()) {
        return nullptr;
    }
    return payload_.empty() ? nullptr : payload_.data();
}

} // namespace tcpmsg