#include "InboundConnection.h"

#include <vector>

namespace tcpmsg {

InboundConnection::ReceiveResult
InboundConnection::receiveOne(SocketServer::Connection& conn,
                              ReceivedData& out,
                              uint32_t timeoutMs) {
    if (!conn.isValid()) {
        return ReceiveResult::InvalidArgument;
    }

    FrameAccumulator acc;

    while (!acc.complete() && !acc.invalid()) {
        uint8_t byte = 0;
        if (!conn.readExact(&byte, 1, timeoutMs)) {
            return ReceiveResult::ReadFailed;
        }
        acc.feed(byte);
    }

    if (acc.invalid()) {
        return ReceiveResult::InvalidFrame;
    }

    if (acc.frameKind() != FrameAccumulator::FrameKind::Data) {
        return ReceiveResult::NotDataFrame;
    }

    TransportCodec::ParsedDataPayload parsed;
    if (!TransportCodec::parseDataPayload(acc.payload(), acc.payloadLen(), parsed)) {
        return ReceiveResult::ParseFailed;
    }

    out.srcMac = parsed.srcMac;
    out.dstMac = parsed.dstMac;
    out.seq = parsed.seq;
    out.peerIp = conn.peerIP();
    out.peerPort = conn.peerPort();
    out.payload.clear();
    out.payload.resize(parsed.payloadLen);

    for (uint16_t i = 0; i < parsed.payloadLen; ++i) {
        out.payload[i] = parsed.payload[i];
    }

    return ReceiveResult::Ok;
}

InboundConnection::AckResult
InboundConnection::sendAck(SocketServer::Connection& conn,
                           uint16_t seq,
                           TransportCodec::AckCode code,
                           uint32_t timeoutMs,
                           uint8_t flags) {
    if (!conn.isValid()) {
        return AckResult::InvalidArgument;
    }

    std::vector<uint8_t> ackFrame;
    if (!TransportCodec::buildAckFrame(ackFrame, seq, code, flags)) {
        return AckResult::BuildFailed;
    }

    if (!conn.writeExact(ackFrame.data(),
                         static_cast<uint16_t>(ackFrame.size()),
                         timeoutMs)) {
        return AckResult::WriteFailed;
    }

    return AckResult::Ok;
}

} // namespace tcpmsg