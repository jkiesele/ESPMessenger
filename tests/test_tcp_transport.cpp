// c++ -std=c++17 -Wall -Wextra -pedantic -pthread SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp OutboundTransaction.cpp PlatformThreads.cpp PlatformMutex.cpp TCPTransport.cpp test_tcp_transport.cpp -o test_tcp_transport

#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "TCPTransport.h"
#include "SocketServer.h"
#include "SocketUtils.h"
#include "TransportCodec.h"
#include "FrameAccumulator.h"
#include "InboundConnection.h"
#include "MACAddress.h"

using tcpmsg::TCPTransport;
using tcpmsg::SocketServer;
using tcpmsg::SocketUtils;
using tcpmsg::TransportCodec;
using tcpmsg::FrameAccumulator;
using tcpmsg::MACAddress;
using tcpmsg::InboundConnection;

namespace {

constexpr uint16_t kTransportPort = 12345;
constexpr uint16_t kPeerPort      = 12346;
constexpr uint32_t kTimeoutMs     = 2000;

const IPAddress kLocalIp(127, 0, 0, 1);

MACAddress makeMac(uint8_t a0, uint8_t a1, uint8_t a2,
                   uint8_t a3, uint8_t a4, uint8_t a5) {
    const uint8_t raw[6] = {a0, a1, a2, a3, a4, a5};
    return MACAddress(raw);
}

bool readOneFrame(SocketServer::Connection& conn, FrameAccumulator& acc, uint32_t timeoutMs) {
    while (!acc.complete() && !acc.invalid()) {
        uint8_t byte = 0;
        if (!conn.readExact(&byte, 1, timeoutMs)) {
            return false;
        }
        acc.feed(byte);
    }
    return acc.complete() && !acc.invalid();
}

enum class PeerServerMode : uint8_t {
    AckOk,
    AckWrongDestination,
    AckQueueFull
};

struct PeerServerResult {
    bool ok = false;
    bool gotData = false;
    MACAddress srcMac;
    MACAddress dstMac;
    uint16_t seq = 0;
    std::vector<uint8_t> payload;
};

void peerServerWorker(PeerServerMode mode,
                      PeerServerResult* outResult) {
    PeerServerResult result{};

    SocketServer server;
    if (!server.begin(kPeerPort)) {
        *outResult = result;
        return;
    }

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        *outResult = result;
        return;
    }

    FrameAccumulator acc;
    if (!readOneFrame(conn, acc, kTimeoutMs)) {
        *outResult = result;
        return;
    }

    if (acc.frameKind() != FrameAccumulator::FrameKind::Data) {
        *outResult = result;
        return;
    }

    TransportCodec::ParsedDataPayload parsed;
    if (!TransportCodec::parseDataPayload(acc.payload(), acc.payloadLen(), parsed)) {
        *outResult = result;
        return;
    }

    result.gotData = true;
    result.srcMac = parsed.srcMac;
    result.dstMac = parsed.dstMac;
    result.seq = parsed.seq;
    result.payload.assign(parsed.payload, parsed.payload + parsed.payloadLen);

    TransportCodec::AckCode ackCode = TransportCodec::AckCode::Ok;
    if (mode == PeerServerMode::AckWrongDestination) {
        ackCode = TransportCodec::AckCode::WrongDestination;
    } else if (mode == PeerServerMode::AckQueueFull) {
        ackCode = TransportCodec::AckCode::QueueFull;
    }

    std::vector<uint8_t> ackFrame;
    if (!TransportCodec::buildAckFrame(ackFrame, parsed.seq, ackCode, 0)) {
        *outResult = result;
        return;
    }

    result.ok = conn.writeExact(ackFrame.data(),
                                static_cast<uint16_t>(ackFrame.size()),
                                kTimeoutMs);
    *outResult = result;
}

struct RawClientResult {
    bool ok = false;
    bool gotAck = false;
    TransportCodec::ParsedAckPayload ack{};
};

void rawClientSendDataAndReadAck(const MACAddress& srcMac,
                                 const MACAddress& dstMac,
                                 uint16_t seq,
                                 const std::vector<uint8_t>& payload,
                                 RawClientResult* outResult) {
    RawClientResult result{};

    int fd = SocketUtils::connectTo(kLocalIp, kTransportPort, kTimeoutMs);
    if (fd < 0) {
        *outResult = result;
        return;
    }

    std::vector<uint8_t> frame;
    if (!TransportCodec::buildDataFrame(frame,
                                        srcMac,
                                        dstMac,
                                        seq,
                                        payload.empty() ? nullptr : payload.data(),
                                        static_cast<uint16_t>(payload.size()))) {
        SocketUtils::closeSocket(fd);
        *outResult = result;
        return;
    }

    if (!SocketUtils::writeExact(fd,
                                 frame.data(),
                                 static_cast<uint16_t>(frame.size()),
                                 kTimeoutMs)) {
        SocketUtils::closeSocket(fd);
        *outResult = result;
        return;
    }

    FrameAccumulator acc;
    while (!acc.complete() && !acc.invalid()) {
        uint8_t byte = 0;
        if (!SocketUtils::readExact(fd, &byte, 1, kTimeoutMs)) {
            SocketUtils::closeSocket(fd);
            *outResult = result;
            return;
        }
        acc.feed(byte);
    }

    if (acc.invalid() || acc.frameKind() != FrameAccumulator::FrameKind::Ack) {
        SocketUtils::closeSocket(fd);
        *outResult = result;
        return;
    }

    TransportCodec::ParsedAckPayload ack;
    if (!TransportCodec::parseAckPayload(acc.payload(), acc.payloadLen(), ack)) {
        SocketUtils::closeSocket(fd);
        *outResult = result;
        return;
    }

    result.ok = true;
    result.gotAck = true;
    result.ack = ack;

    SocketUtils::closeSocket(fd);
    *outResult = result;
}

bool testSendToIPOk() {
    TCPTransport tx;
    const MACAddress localMac = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress peerMac  = makeMac(10, 11, 12, 13, 14, 15);

    if (!tx.begin(kTransportPort, localMac)) return false;

    PeerServerResult peerResult{};
    std::thread peer(peerServerWorker, PeerServerMode::AckOk, &peerResult);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const uint8_t payload[] = {0xAA, 0xBB, 0xCC};
    const auto rc = tx.sendToIP(payload,
                                sizeof(payload),
                                kLocalIp,
                                kPeerPort,
                                peerMac,
                                kTimeoutMs);

    peer.join();
    tx.end();

    return rc == TCPTransport::Result::Ok &&
           peerResult.ok &&
           peerResult.gotData &&
           peerResult.srcMac == localMac &&
           peerResult.dstMac == peerMac &&
           peerResult.payload.size() == 3 &&
           peerResult.payload[0] == 0xAA &&
           peerResult.payload[1] == 0xBB &&
           peerResult.payload[2] == 0xCC;
}

bool testSendToIPRemoteQueueFull() {
    TCPTransport tx;
    const MACAddress localMac = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress peerMac  = makeMac(10, 11, 12, 13, 14, 15);

    if (!tx.begin(kTransportPort, localMac)) return false;

    PeerServerResult peerResult{};
    std::thread peer(peerServerWorker, PeerServerMode::AckQueueFull, &peerResult);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const uint8_t payload[] = {0x01};
    const auto rc = tx.sendToIP(payload,
                                sizeof(payload),
                                kLocalIp,
                                kPeerPort,
                                peerMac,
                                kTimeoutMs);

    peer.join();
    tx.end();

    return rc == TCPTransport::Result::RemoteQueueFull &&
           peerResult.ok &&
           peerResult.gotData;
}

bool testReceiveAndPopMessage() {
    TCPTransport tx;
    const MACAddress localMac = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress srcMac   = makeMac(10, 11, 12, 13, 14, 15);

    if (!tx.begin(kTransportPort, localMac)) return false;

    RawClientResult clientResult{};
    const std::vector<uint8_t> payload = {0x41, 0x42, 0x43};
    std::thread client(rawClientSendDataAndReadAck,
                       srcMac,
                       localMac,
                       0x1111,
                       payload,
                       &clientResult);

    client.join();

    TCPTransport::Message msg;
    bool got = false;
    for (int i = 0; i < 20; ++i) {
        if (tx.popReceivedMessage(msg)) {
            got = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    tx.end();

    return clientResult.ok &&
           clientResult.gotAck &&
           clientResult.ack.code == TransportCodec::AckCode::Ok &&
           got &&
           msg.srcMac == srcMac &&
           msg.dstMac == localMac &&
           msg.seq == 0x1111 &&
           msg.payload.size() == 3 &&
           msg.payload[0] == 0x41 &&
           msg.payload[1] == 0x42 &&
           msg.payload[2] == 0x43;
}

bool testWrongDestinationAck() {
    TCPTransport tx;
    const MACAddress localMac = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress srcMac   = makeMac(10, 11, 12, 13, 14, 15);
    const MACAddress wrongMac = makeMac(99, 98, 97, 96, 95, 94);

    if (!tx.begin(kTransportPort, localMac)) return false;

    RawClientResult clientResult{};
    const std::vector<uint8_t> payload = {0x55};
    std::thread client(rawClientSendDataAndReadAck,
                       srcMac,
                       wrongMac,
                       0x2222,
                       payload,
                       &clientResult);

    client.join();

    TCPTransport::Message msg;
    const bool gotMessage = tx.popReceivedMessage(msg);

    tx.end();

    return clientResult.ok &&
           clientResult.gotAck &&
           clientResult.ack.code == TransportCodec::AckCode::WrongDestination &&
           !gotMessage;
}

bool testDuplicateSuppression() {
    TCPTransport tx;
    const MACAddress localMac = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress srcMac   = makeMac(10, 11, 12, 13, 14, 15);

    if (!tx.begin(kTransportPort, localMac)) return false;

    RawClientResult c1{};
    RawClientResult c2{};
    const std::vector<uint8_t> payload = {0x77, 0x88};

    std::thread client1(rawClientSendDataAndReadAck,
                        srcMac,
                        localMac,
                        0x3333,
                        payload,
                        &c1);
    client1.join();

    std::thread client2(rawClientSendDataAndReadAck,
                        srcMac,
                        localMac,
                        0x3333,
                        payload,
                        &c2);
    client2.join();

    int popped = 0;
    TCPTransport::Message msg;
    for (int i = 0; i < 20; ++i) {
        while (tx.popReceivedMessage(msg)) {
            ++popped;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    tx.end();

    return c1.ok && c1.gotAck && c1.ack.code == TransportCodec::AckCode::Ok &&
           c2.ok && c2.gotAck && c2.ack.code == TransportCodec::AckCode::Ok &&
           popped == 1;
}

using TestFn = bool(*)();

bool runTest(const char* name, TestFn fn) {
    std::cout << "[RUN ] " << name << "\n";
    const bool ok = fn();
    std::cout << (ok ? "[ OK ] " : "[FAIL] ") << name << "\n";
    return ok;
}

} // namespace

int main() {
    int fails = 0;

    if (!runTest("send_to_ip_ok", testSendToIPOk)) ++fails;
    if (!runTest("send_to_ip_remote_queue_full", testSendToIPRemoteQueueFull)) ++fails;
    if (!runTest("receive_and_pop_message", testReceiveAndPopMessage)) ++fails;
    if (!runTest("wrong_destination_ack", testWrongDestinationAck)) ++fails;
    if (!runTest("duplicate_suppression", testDuplicateSuppression)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all TCPTransport tests passed\n";
    return 0;
}