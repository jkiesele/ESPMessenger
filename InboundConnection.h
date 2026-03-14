#pragma once

#include <cstdint>
#include <vector>

#include "PlatformNet.h"
#include "SocketServer.h"
#include "FrameAccumulator.h"
#include "TransportCodec.h"
#include "Helpers.h"

namespace tcpmsg {

class InboundConnection {
public:
    enum class ReceiveResult : uint8_t {
        Ok = 0,
        InvalidArgument,
        ReadFailed,
        InvalidFrame,
        NotDataFrame,
        ParseFailed
    };

    enum class AckResult : uint8_t {
        Ok = 0,
        InvalidArgument,
        BuildFailed,
        WriteFailed
    };

    struct ReceivedData {
        IPAddress peerIp;
        uint16_t peerPort = 0;
        MACAddress srcMac;
        MACAddress dstMac;
        uint16_t seq = 0;
        std::vector<uint8_t> payload;
    };

    static ReceiveResult receiveOne(SocketServer::Connection& conn,
                                    ReceivedData& out,
                                    uint32_t timeoutMs);

    static AckResult sendAck(SocketServer::Connection& conn,
                             uint16_t seq,
                             TransportCodec::AckCode code,
                             uint32_t timeoutMs,
                             uint8_t flags = 0);
};

} // namespace tcpmsg