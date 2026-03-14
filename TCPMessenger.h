#pragma once

#include <cstdint>
#include <vector>

#include "PlatformNet.h"
#include "PlatformThreads.h"
#include "PlatformMutex.h"
#include "TCPTransport.h"
#include "EncryptionHandler.h"
#include "Serializable.h"

namespace tcpmsg {

class TCPMessenger {
public:
    enum class Result : uint8_t {
        Ok = 0,
        NoMessage,
        NotRunning,
        Busy,
        InvalidArgument,
        TooLarge,
        SerializeFailed,
        EncryptFailed,
        DecryptFailed,
        InvalidEnvelope,
        TransportError,
        RetryLimitReached
    };

    struct SendOptions {
        uint32_t timeoutMs = 1000;
        uint8_t maxRetries = 3;
        uint32_t retryDelayMs = 0;
    };

    struct SendResult {
        Result rc = Result::TransportError;
        IPAddress ip;
        uint16_t port = 0;
    };

    struct ReceivedMessage {
        IPAddress peerIp;
        uint16_t peerPort = 0;

        MACAddress srcMac;
        MACAddress dstMac;
        uint16_t seq = 0;

        uint8_t type = 0;
        uint8_t chanId = 0;

        std::vector<uint8_t> payload; // decrypted plaintext payload
    };

    TCPMessenger() = default;
    ~TCPMessenger();

    TCPMessenger(const TCPMessenger&) = delete;
    TCPMessenger& operator=(const TCPMessenger&) = delete;

    bool begin(uint16_t listenPort,
               const MACAddress& localMac,
               EncryptionHandler* encryptionHandler);
    void end();

    bool isRunning() const;

    Result sendToIP(const Serializable& obj,
                uint8_t chanId,
                const IPAddress& ip,
                uint16_t port,
                const MACAddress& expectedDstMac);

    Result sendToIP(const Serializable& obj,
                uint8_t chanId,
                const IPAddress& ip,
                uint16_t port,
                const MACAddress& expectedDstMac,
                const SendOptions& options);

    bool popSendResult(SendResult& out);

    bool popReceivedMessage(ReceivedMessage& out, Result& rc);

private:
    struct PendingSend {
        IPAddress ip;
        uint16_t port = 0;
        MACAddress expectedDstMac;

        std::vector<uint8_t> transportPayload;
        SendOptions options;
    };

    static void sendThreadMain(void* ctx);
    void sendLoop();

    Result buildOutgoingTransportPayload(const Serializable& obj,
                                         uint8_t chanId,
                                         std::vector<uint8_t>& outTransportPayload);

    Result decodeIncomingTransportMessage(const TCPTransport::Message& in,
                                          ReceivedMessage& out);

    static bool isRetryable(TCPTransport::Result rc);
    static Result mapTransportResult(TCPTransport::Result rc, bool retriesExhausted);

private:
    static constexpr uint32_t kTxPollSleepMs = 10;

    mutable PlatformMutex mutex_;

    TCPTransport transport_;
    EncryptionHandler* encryptionHandler_ = nullptr;

    PlatformThread sendThread_;

    bool running_ = false;
    bool sendPending_ = false;

    PendingSend pendingSend_;
    bool sendResultReady_ = false;
    SendResult sendResult_;
};

} // namespace tcpmsg