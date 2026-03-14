#include "TCPMessenger.h"

#include <vector>

#include "MessengerCodec.h"

namespace tcpmsg {

TCPMessenger::~TCPMessenger() {
    end();
}

bool TCPMessenger::begin(uint16_t listenPort,
                         const MACAddress& localMac,
                         EncryptionHandler* encryptionHandler) {
    end();

    if (listenPort == 0 || encryptionHandler == nullptr) {
        return false;
    }

    if (!transport_.begin(listenPort, localMac)) {
        return false;
    }

    {
        PlatformLockGuard lock(mutex_);
        encryptionHandler_ = encryptionHandler;
        running_ = true;
        sendPending_ = false;
        sendResultReady_ = false;
    }

    if (!sendThread_.start(&TCPMessenger::sendThreadMain, this, "tcpmsg_tx", 4096)) {
        transport_.end();
        PlatformLockGuard lock(mutex_);
        encryptionHandler_ = nullptr;
        running_ = false;
        return false;
    }

    return true;
}

void TCPMessenger::end() {
    {
        PlatformLockGuard lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
        sendPending_ = false;
    }

    transport_.end();
    sendThread_.waitUntilStopped(5000);

    PlatformLockGuard lock(mutex_);
    encryptionHandler_ = nullptr;
}

bool TCPMessenger::isRunning() const {
    PlatformLockGuard lock(mutex_);
    return running_;
}

TCPMessenger::Result TCPMessenger::sendToIP(const Serializable& obj,
                                            uint8_t chanId,
                                            const IPAddress& ip,
                                            uint16_t port,
                                            const MACAddress& expectedDstMac,
                                            const SendOptions& options) {
    if (port == 0) {
        return Result::InvalidArgument;
    }

    std::vector<uint8_t> transportPayload;
    const Result buildRc = buildOutgoingTransportPayload(obj, chanId, transportPayload);
    if (buildRc != Result::Ok) {
        return buildRc;
    }

    PlatformLockGuard lock(mutex_);

    if (!running_) {
        return Result::NotRunning;
    }

    if (sendPending_) {
        return Result::Busy;
    }

    pendingSend_.ip = ip;
    pendingSend_.port = port;
    pendingSend_.expectedDstMac = expectedDstMac;
    pendingSend_.type = obj.typeId();
    pendingSend_.chanId = chanId;
    pendingSend_.transportPayload = std::move(transportPayload);
    pendingSend_.options = options;

    sendPending_ = true;
    return Result::Ok;
}

TCPMessenger::Result TCPMessenger::sendToIP(const Serializable& obj,
                                            uint8_t chanId,
                                            const IPAddress& ip,
                                            uint16_t port,
                                            const MACAddress& expectedDstMac) {
    return sendToIP(obj, chanId, ip, port, expectedDstMac, SendOptions{});
}

bool TCPMessenger::popSendResult(SendResult& out) {
    PlatformLockGuard lock(mutex_);

    if (!sendResultReady_) {
        return false;
    }

    out = sendResult_;
    sendResultReady_ = false;
    return true;
}

bool TCPMessenger::popReceivedMessage(ReceivedMessage& out, Result& rc) {
    {
        PlatformLockGuard lock(mutex_);
        if (!running_) {
            rc = Result::NotRunning;
            return false;
        }
    }

    TCPTransport::Message in;
    if (!transport_.popReceivedMessage(in)) {
        rc = Result::NoMessage;
        return false;
    }

    rc = decodeIncomingTransportMessage(in, out);
    return rc == Result::Ok;
}

void TCPMessenger::sendThreadMain(void* ctx) {
    if (!ctx) return;
    static_cast<TCPMessenger*>(ctx)->sendLoop();
}

void TCPMessenger::sendLoop() {
    while (true) {
        PendingSend job;
        bool haveJob = false;
        bool running = false;

        {
            PlatformLockGuard lock(mutex_);
            running = running_;
            if (running_ && sendPending_) {
                job = std::move(pendingSend_);
                sendPending_ = false;
                haveJob = true;
            }
        }

        if (!running) {
            break;
        }

        if (!haveJob) {
            PlatformThread::sleepMs(kTxPollSleepMs);
            continue;
        }

        SendResult finalResult;
        finalResult.ip = job.ip;
        finalResult.port = job.port;
        finalResult.rc = Result::TransportError;

        const uint8_t maxAttempts = static_cast<uint8_t>(job.options.maxRetries + 1);
        bool success = false;

        for (uint8_t attempt = 0; attempt < maxAttempts; ++attempt) {
            const TCPTransport::Result txRc =
                transport_.sendToIP(job.transportPayload.data(),
                                    static_cast<uint16_t>(job.transportPayload.size()),
                                    job.ip,
                                    job.port,
                                    job.expectedDstMac,
                                    job.options.timeoutMs);

            if (txRc == TCPTransport::Result::Ok) {
                finalResult.rc = Result::Ok;
                success = true;
                break;
            }

            if (!isRetryable(txRc)) {
                finalResult.rc = mapTransportResult(txRc, false);
                break;
            }

            const bool lastAttempt = (attempt + 1 >= maxAttempts);
            if (lastAttempt) {
                finalResult.rc = mapTransportResult(txRc, true);
                break;
            }

            if (job.options.retryDelayMs > 0) {
                PlatformThread::sleepMs(job.options.retryDelayMs);
            }
        }

        {
            PlatformLockGuard lock(mutex_);
            sendResult_ = finalResult;
            sendResultReady_ = true;
        }

        (void)success;
    }
}

TCPMessenger::Result
TCPMessenger::buildOutgoingTransportPayload(const Serializable& obj,
                                            uint8_t chanId,
                                            std::vector<uint8_t>& outTransportPayload) {
    EncryptionHandler* enc = nullptr;
    {
        PlatformLockGuard lock(mutex_);
        if (!running_ || encryptionHandler_ == nullptr) {
            return Result::NotRunning;
        }
        enc = encryptionHandler_;
    }

    const uint16_t plaintextLen = obj.payloadSize();
    std::vector<uint8_t> plaintext(plaintextLen);

    if (plaintextLen > 0) {
        obj.serializeTo(plaintext.data());
    }

    const std::vector<uint8_t> encrypted = enc->encrypt(plaintext);

    if (!MessengerCodec::buildMessage(outTransportPayload,
                                      obj.typeId(),
                                      chanId,
                                      encrypted.empty() ? nullptr : encrypted.data(),
                                      static_cast<uint16_t>(encrypted.size()))) {
        return Result::TooLarge;
    }

    return Result::Ok;
}

TCPMessenger::Result
TCPMessenger::decodeIncomingTransportMessage(const TCPTransport::Message& in,
                                             ReceivedMessage& out) {
    EncryptionHandler* enc = nullptr;
    {
        PlatformLockGuard lock(mutex_);
        if (!running_ || encryptionHandler_ == nullptr) {
            return Result::NotRunning;
        }
        enc = encryptionHandler_;
    }

    MessengerCodec::ParsedMessage parsed;
    if (!MessengerCodec::parseMessage(in.payload.data(),
                                      static_cast<uint16_t>(in.payload.size()),
                                      parsed)) {
        return Result::InvalidEnvelope;
    }

    std::vector<uint8_t> encrypted;
    if (parsed.encryptedPayloadLen > 0) {
        encrypted.assign(parsed.encryptedPayload,
                         parsed.encryptedPayload + parsed.encryptedPayloadLen);
    }

    std::vector<uint8_t> plaintext;
    if (!enc->decrypt(encrypted, plaintext)) {
        return Result::DecryptFailed;
    }

    out.peerIp = in.peerIp;
    out.peerPort = in.peerPort;
    out.srcMac = in.srcMac;
    out.dstMac = in.dstMac;
    out.seq = in.seq;
    out.type = parsed.type;
    out.chanId = parsed.chanId;
    out.payload = std::move(plaintext);

    return Result::Ok;
}

bool TCPMessenger::isRetryable(TCPTransport::Result rc) {
    switch (rc) {
        case TCPTransport::Result::ConnectFailed:
        case TCPTransport::Result::WriteFailed:
        case TCPTransport::Result::AckTimeout:
        case TCPTransport::Result::TransportError:
            return true;
        default:
            return false;
    }
}

TCPMessenger::Result
TCPMessenger::mapTransportResult(TCPTransport::Result rc, bool retriesExhausted) {
    if (retriesExhausted) {
        return Result::RetryLimitReached;
    }

    switch (rc) {
        case TCPTransport::Result::Ok:
            return Result::Ok;
        case TCPTransport::Result::NotRunning:
            return Result::NotRunning;
        case TCPTransport::Result::Busy:
            return Result::Busy;
        case TCPTransport::Result::TooLarge:
            return Result::TooLarge;
        case TCPTransport::Result::InvalidArgument:
            return Result::InvalidArgument;
        case TCPTransport::Result::ConnectFailed:
        case TCPTransport::Result::WriteFailed:
        case TCPTransport::Result::AckTimeout:
        case TCPTransport::Result::AckError:
        case TCPTransport::Result::WrongDestination:
        case TCPTransport::Result::RemoteQueueFull:
        case TCPTransport::Result::TransportError:
        default:
            return Result::TransportError;
    }
}

} // namespace tcpmsg