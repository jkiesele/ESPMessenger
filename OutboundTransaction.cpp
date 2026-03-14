#include "OutboundTransaction.h"

namespace tcpmsg {

OutboundTransaction::Result OutboundTransaction::run(const IPAddress& ip,
                                                     uint16_t port,
                                                     const uint8_t* frame,
                                                     uint16_t frameLen,
                                                     uint16_t expectedSeq,
                                                     uint32_t timeoutMs) {
    if ((frame == nullptr && frameLen > 0) || port == 0) {
        return Result::InvalidArgument;
    }

    int fd = SocketUtils::connectTo(ip, port, timeoutMs);
    if (fd < 0) {
        return Result::ConnectFailed;
    }

    if (!SocketUtils::writeExact(fd, frame, frameLen, timeoutMs)) {
        SocketUtils::closeSocket(fd);
        return Result::WriteFailed;
    }

    FrameAccumulator acc;

    while (!acc.complete() && !acc.invalid()) {
        uint8_t byte = 0;
        if (!SocketUtils::readExact(fd, &byte, 1, timeoutMs)) {
            SocketUtils::closeSocket(fd);
            return Result::ReadFailed;
        }
        acc.feed(byte);
    }

    SocketUtils::closeSocket(fd);

    if (acc.invalid()) {
        return Result::AckInvalid;
    }

    if (acc.frameKind() != FrameAccumulator::FrameKind::Ack) {
        return Result::AckInvalid;
    }

    TransportCodec::ParsedAckPayload ack;
    if (!TransportCodec::parseAckPayload(acc.payload(), acc.payloadLen(), ack)) {
        return Result::AckInvalid;
    }

    if (ack.seq != expectedSeq) {
        return Result::AckWrongSequence;
    }

    switch (ack.code) {
        case TransportCodec::AckCode::Ok:
            return Result::Ok;
        case TransportCodec::AckCode::WrongDestination:
            return Result::AckWrongDestination;
        case TransportCodec::AckCode::QueueFull:
            return Result::AckQueueFull;
        case TransportCodec::AckCode::TransportError:
            return Result::AckTransportError;
        default:
            return Result::AckInvalid;
    }
}

} // namespace tcpmsg