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

/**
 * @brief Slim transport layer for opaque payload delivery over TCP.
 *
 * Role in stack:
 * - Sits below TCPMessenger.
 * - Handles only transport concerns:
 *   - local listen socket
 *   - transport framing
 *   - src/dst MAC transport metadata
 *   - sequence numbers
 *   - transport ACK handling
 *   - duplicate suppression
 *   - receive queue
 *
 * What it does not do:
 * - no serialization
 * - no encryption/decryption
 * - no messenger-level type/channel parsing
 * - no hostname or mDNS lookup
 * - no async send worker
 *
 * Threading model:
 * - owns one internal receive thread
 * - receive thread accepts inbound connections and fills the RX queue
 * - sendToIP(...) is blocking
 * - access to shared state is protected by mutex_
 */
class TCPTransport {
public:
    /**
     * @brief Result codes for transport send operations.
     */
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

    /**
     * @brief One received transport-level message.
     *
     * peerIp / peerPort:
     * - socket-level sender information
     *
     * srcMac / dstMac / seq:
     * - transport-level metadata from the DATA payload
     *
     * payload:
     * - opaque transport payload bytes for the higher layer
     */
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

    /**
     * @brief Start the transport listener and receive thread.
     *
     * @param listenPort Local TCP port to listen on.
     * @param localMac Local transport MAC used for destination checks and outbound frames.
     *
     * @return true on success, false on failure.
     *
     * Notes:
     * - begin() resets internal runtime state.
     * - calling begin() on an already running instance restarts it.
     */
    bool begin(uint16_t listenPort, const MACAddress& localMac);

    /**
     * @brief Stop receive thread and listener.
     *
     * Safe to call repeatedly.
     */
    void end();

    /**
     * @brief Send one opaque payload to a concrete IP/port as one blocking transport transaction.
     *
     * Steps:
     * - validate arguments
     * - build one transport DATA frame
     * - connect to peer
     * - send frame
     * - wait for transport ACK
     *
     * @param payload Opaque higher-layer payload bytes.
     * @param payloadLen Number of bytes in payload.
     * @param ip Destination IP.
     * @param port Destination TCP port.
     * @param expectedDstMac Destination transport MAC to place into the DATA frame.
     * @param timeoutMs Timeout for one blocking transport transaction.
     *
     * @return Final transport result.
     *
     * Notes:
     * - only one outbound send is allowed at a time
     * - this function blocks until ACK, failure, or timeout
     */
    Result sendToIP(const uint8_t* payload,
                    uint16_t payloadLen,
                    const IPAddress& ip,
                    uint16_t port,
                    const MACAddress& expectedDstMac,
                    uint32_t timeoutMs);

    /**
     * @brief Pop one received transport message from the RX queue.
     *
     * @param out Receives the oldest queued message.
     *
     * @return true if a message was available, false otherwise.
     *
     * Notes:
     * - polling API
     * - queue is filled by the internal receive thread
     */
    bool popReceivedMessage(Message& out);

    /**
     * @brief Check whether transport is currently running.
     */
    bool isRunning() const;

private:
    /**
     * @brief Small duplicate cache entry keyed by (srcMac, seq).
     */
    struct SeenPacket {
        MACAddress srcMac;
        uint16_t seq = 0;
    };

    static void rxThreadMain(void* ctx);
    void rxLoop();
    void handleAcceptedConnection(SocketServer::Connection&& conn);

    /**
     * @brief Duplicate-cache helpers.
     *
     * These functions require mutex_ to already be held.
     */
    bool isDuplicateLocked(const MACAddress& srcMac, uint16_t seq) const;
    void rememberDuplicateLocked(const MACAddress& srcMac, uint16_t seq);

    /**
     * @brief Map blocking outbound transaction results into transport API results.
     */
    static Result mapOutboundResult(OutboundTransaction::Result r);

private:
    /**
     * RX queue hard limit.
     * If full, inbound packets are ACKed with QueueFull and not enqueued.
     */
    static constexpr size_t kRxQueueMaxSize = 8;

    /**
     * Number of recent (srcMac, seq) pairs remembered for duplicate suppression.
     */
    static constexpr size_t kDuplicateCacheSize = 8;

    /**
     * Timeout used by the receive thread when waiting for accepted connections.
     * Kept finite so shutdown can be observed promptly.
     */
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