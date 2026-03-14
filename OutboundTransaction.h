#pragma once

#include <cstdint>

#include "PlatformNet.h"
#include "SocketUtils.h"
#include "FrameAccumulator.h"
#include "TransportCodec.h"

namespace tcpmsg {

class OutboundTransaction {
public:
    enum class Result : uint8_t {
        Ok = 0,
        InvalidArgument,
        ConnectFailed,
        WriteFailed,
        ReadFailed,
        AckTimeout,
        AckInvalid,
        AckWrongSequence,
        AckWrongDestination,
        AckQueueFull,
        AckTransportError
    };

    static Result run(const IPAddress& ip,
                      uint16_t port,
                      const uint8_t* frame,
                      uint16_t frameLen,
                      uint16_t expectedSeq,
                      uint32_t timeoutMs);
};

} // namespace tcpmsg