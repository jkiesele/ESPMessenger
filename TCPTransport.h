#pragma once

#include <cstdint>
#include <deque>
#include <vector>

#include "Config.h"
#include "Helpers.h"
#include "PlatformNet.h"
#include "PlatformThreads.h"
#include "PlatformMutex.h"
#include "SocketServer.h"
#include "InboundConnection.h"
#include "OutboundTransaction.h"
#include "TransportCodec.h"

namespace tcpmsg {

class TCPTransport {
public:
    enum class Result : uint8_t {
        Ok = 0,
        NotRunning,
        Busy,
        TooLarge,
        InvalidArgument,
        ConnectFailed,
        WriteFailed,
        AckTimeout,
        AckError,
        WrongDestination,
        RemoteQueueFull,
        TransportError
    };

    struct Message {
        IPAddress peerIp;
        uint16_t peerPort = 0;

        MACAddress srcMac;
        MACAddress dstMac;
        uint16_t seq = 0;

        std::vector<uint8_t> payload;
    };

    TCPTransport() = default;
    ~TCPTransport();

    TCPTransport(const TCPTransport&) = delete;
    TCPTransport& operator=(const TCPTransport&) = delete;

    bool begin(uint16_t listenPort, const MACAddress& localMac);
    void end();

    Result sendToIP(const uint8_t* payload,
                    uint16_t payloadLen,
                    const IPAddress& ip,
                    uint16_t port,
                    const MACAddress& expectedDstMac,
                    uint32_t timeoutMs);

    bool popReceivedMessage(Message& out);

    bool isRunning() const;

private:
    struct SeenPacket {
        MACAddress srcMac;
        uint16_t seq = 0;
    };

    static void rxThreadMain(void* ctx);
    void rxLoop();
    void handleAcceptedConnection(SocketServer::Connection&& conn);

    bool isDuplicateLocked(const MACAddress& srcMac, uint16_t seq) const;
    void rememberDuplicateLocked(const MACAddress& srcMac, uint16_t seq);

    static Result mapOutboundResult(OutboundTransaction::Result r);

private:
    static constexpr size_t kRxQueueMaxSize = 8;
    static constexpr size_t kDuplicateCacheSize = 8;
    static constexpr uint32_t kAcceptTimeoutMs = 200;

    mutable PlatformMutex mutex_;

    SocketServer server_;
    PlatformThread rxThread_;

    bool running_ = false;
    bool sendBusy_ = false;
    uint16_t nextSeq_ = 0;

    MACAddress localMac_;

    std::deque<Message> rxQueue_;
    std::deque<SeenPacket> duplicateCache_;
};

} // namespace tcpmsg