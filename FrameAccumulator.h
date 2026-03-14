#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include "Config.h"

namespace tcpmsg {

class FrameAccumulator {
public:
    enum class FrameKind : uint8_t {
        Invalid = 0,
        Data    = 1,
        Ack     = 2
    };


    FrameAccumulator() = default;

    void reset();

    // Feeds one byte into the accumulator.
    // Returns true iff a complete frame became available with this byte.
    bool feed(uint8_t byte);

    bool complete() const { return state_ == State::Complete; }
    bool invalid()  const { return state_ == State::Invalid;  }

    FrameKind frameKind() const;
    uint16_t payloadLen() const;
    const uint8_t* payload() const;

    static constexpr uint16_t kHeaderSize = 4;

private:
    enum class State : uint8_t {
        ReadingHeader,
        ReadingPayload,
        Complete,
        Invalid
    };


    static FrameKind decodeFrameKind(uint8_t raw);

    uint8_t  header_[kHeaderSize] = {0, 0, 0, 0};
    uint8_t  headerBytes_ = 0;
    uint16_t payloadBytes_ = 0;

    std::vector<uint8_t> payload_;
    State state_ = State::ReadingHeader;
};

} // namespace tcpmsg