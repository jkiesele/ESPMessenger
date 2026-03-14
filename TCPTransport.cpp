#include "TCPTransport.h"

namespace tcpmsg {

TCPTransport::~TCPTransport() {
    end();
}

bool TCPTransport::begin(uint16_t listenPort, const MACAddress& localMac) {
    end();

    if (listenPort == 0) {
        return false;
    }

    if (!server_.begin(listenPort)) {
        return false;
    }

    {
        PlatformLockGuard lock(mutex_);
        localMac_ = localMac;
        rxQueue_.clear();
        duplicateCache_.clear();
        sendBusy_ = false;
        running_ = true;
    }

    if (!rxThread_.start(&TCPTransport::rxThreadMain, this, "tcp_rx", 4096)) {
        server_.end();
        PlatformLockGuard lock(mutex_);
        running_ = false;
        return false;
    }

    return true;
}

void TCPTransport::end() {
    {
        PlatformLockGuard lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
    }

    server_.end();
    rxThread_.waitUntilStopped(5000);

    PlatformLockGuard lock(mutex_);
    sendBusy_ = false;
}

TCPTransport::Result TCPTransport::sendToIP(const uint8_t* payload,
                                            uint16_t payloadLen,
                                            const IPAddress& ip,
                                            uint16_t port,
                                            const MACAddress& expectedDstMac,
                                            uint32_t timeoutMs) {
    if (port == 0 || (payload == nullptr && payloadLen > 0)) {
        return Result::InvalidArgument;
    }

    if (payloadLen > kFrameMaxPayloadLen - TransportCodec::kDataHeaderSize) {
        return Result::TooLarge;
    }

    uint16_t seq = 0;

    {
        PlatformLockGuard lock(mutex_);

        if (!running_) {
            return Result::NotRunning;
        }

        if (sendBusy_) {
            return Result::Busy;
        }

        sendBusy_ = true;
        seq = nextSeq_++;
    }

    std::vector<uint8_t> frame;
    Result result = Result::TransportError;

    if (!TransportCodec::buildDataFrame(frame,
                                        localMac_,
                                        expectedDstMac,
                                        seq,
                                        payload,
                                        payloadLen)) {
        result = Result::TooLarge;
    } else {
        result = mapOutboundResult(
            OutboundTransaction::run(ip,
                                     port,
                                     frame.data(),
                                     static_cast<uint16_t>(frame.size()),
                                     seq,
                                     timeoutMs));
    }

    {
        PlatformLockGuard lock(mutex_);
        sendBusy_ = false;
    }

    return result;
}

bool TCPTransport::popReceivedMessage(Message& out) {
    PlatformLockGuard lock(mutex_);

    if (rxQueue_.empty()) {
        return false;
    }

    out = std::move(rxQueue_.front());
    rxQueue_.pop_front();
    return true;
}

bool TCPTransport::isRunning() const {
    PlatformLockGuard lock(mutex_);
    return running_;
}

void TCPTransport::rxThreadMain(void* ctx) {
    if (!ctx) return;
    static_cast<TCPTransport*>(ctx)->rxLoop();
}

void TCPTransport::rxLoop() {
    while (true) {
        {
            PlatformLockGuard lock(mutex_);
            if (!running_) {
                break;
            }
        }

        auto conn = server_.accept(kAcceptTimeoutMs);
        if (!conn.isValid()) {
            continue;
        }

        handleAcceptedConnection(std::move(conn));
    }
}

void TCPTransport::handleAcceptedConnection(SocketServer::Connection&& conn) {
    InboundConnection::ReceivedData data;
    const auto recvRc = InboundConnection::receiveOne(conn, data, kAcceptTimeoutMs);

    if (recvRc != InboundConnection::ReceiveResult::Ok) {
        return;
    }

    TransportCodec::AckCode ackCode = TransportCodec::AckCode::TransportError;

    {
        PlatformLockGuard lock(mutex_);

        if (data.dstMac != localMac_) {
            ackCode = TransportCodec::AckCode::WrongDestination;
        } else if (isDuplicateLocked(data.srcMac, data.seq)) {
            ackCode = TransportCodec::AckCode::Ok;
        } else if (rxQueue_.size() >= kRxQueueMaxSize) {
            ackCode = TransportCodec::AckCode::QueueFull;
        } else {
            Message msg;
            msg.peerIp = data.peerIp;
            msg.peerPort = data.peerPort;
            msg.srcMac = data.srcMac;
            msg.dstMac = data.dstMac;
            msg.seq = data.seq;
            msg.payload = std::move(data.payload);

            rxQueue_.push_back(std::move(msg));
            rememberDuplicateLocked(data.srcMac, data.seq);
            ackCode = TransportCodec::AckCode::Ok;
        }
    }

    InboundConnection::sendAck(conn, data.seq, ackCode, kAcceptTimeoutMs, 0);
}

bool TCPTransport::isDuplicateLocked(const MACAddress& srcMac, uint16_t seq) const {
    for (const auto& p : duplicateCache_) {
        if (p.seq == seq && p.srcMac == srcMac) {
            return true;
        }
    }
    return false;
}

void TCPTransport::rememberDuplicateLocked(const MACAddress& srcMac, uint16_t seq) {
    SeenPacket p;
    p.srcMac = srcMac;
    p.seq = seq;

    duplicateCache_.push_back(p);
    while (duplicateCache_.size() > kDuplicateCacheSize) {
        duplicateCache_.pop_front();
    }
}

TCPTransport::Result TCPTransport::mapOutboundResult(OutboundTransaction::Result r) {
    switch (r) {
        case OutboundTransaction::Result::Ok:
            return Result::Ok;
        case OutboundTransaction::Result::InvalidArgument:
            return Result::InvalidArgument;
        case OutboundTransaction::Result::ConnectFailed:
            return Result::ConnectFailed;
        case OutboundTransaction::Result::WriteFailed:
            return Result::WriteFailed;
        case OutboundTransaction::Result::ReadFailed:
        case OutboundTransaction::Result::AckTimeout:
            return Result::AckTimeout;
        case OutboundTransaction::Result::AckWrongDestination:
            return Result::WrongDestination;
        case OutboundTransaction::Result::AckQueueFull:
            return Result::RemoteQueueFull;
        case OutboundTransaction::Result::AckWrongSequence:
        case OutboundTransaction::Result::AckInvalid:
            return Result::AckError;
        case OutboundTransaction::Result::AckTransportError:
            return Result::TransportError;
        default:
            return Result::TransportError;
    }
}

} // namespace tcpmsg