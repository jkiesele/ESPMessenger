//c++ -std=c++17 -Wall -Wextra -pedantic -pthread SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp test_inbound_connection.cpp  -o test_inbound_connection

#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "InboundConnection.h"
#include "SocketUtils.h"
#include "SocketServer.h"
#include "TransportCodec.h"
#include "FrameAccumulator.h"
#include "Helpers.h"

using tcpmsg::InboundConnection;
using tcpmsg::SocketServer;
using tcpmsg::SocketUtils;
using tcpmsg::TransportCodec;
using tcpmsg::FrameAccumulator;
using tcpmsg::MACAddress;

namespace {

constexpr uint16_t kPort = 12345;
constexpr uint32_t kTimeoutMs = 2000;
const IPAddress kIp(127, 0, 0, 1);

MACAddress makeMac(uint8_t a0, uint8_t a1, uint8_t a2,
                   uint8_t a3, uint8_t a4, uint8_t a5) {
    const uint8_t raw[6] = {a0, a1, a2, a3, a4, a5};
    return MACAddress(raw);
}

bool readOneFrame(int fd, FrameAccumulator& acc, uint32_t timeoutMs) {
    while (!acc.complete() && !acc.invalid()) {
        uint8_t byte = 0;
        if (!SocketUtils::readExact(fd, &byte, 1, timeoutMs)) {
            return false;
        }
        acc.feed(byte);
    }
    return acc.complete() && !acc.invalid();
}

enum class ClientMode : uint8_t {
    SendValidData,
    SendAckFrame,
    SendInvalidFrame,
    ReceiveAckOnly
};

struct ClientResult {
    bool ok = false;
    bool gotAck = false;
    TransportCodec::ParsedAckPayload ack{};
};

void clientWorker(ClientMode mode,
                  uint16_t seq,
                  ClientResult* outResult) {
    ClientResult result{};

    int fd = SocketUtils::connectTo(kIp, kPort, kTimeoutMs);
    if (fd < 0) {
        *outResult = result;
        return;
    }

    if (mode == ClientMode::ReceiveAckOnly) {
        FrameAccumulator acc;
        if (!readOneFrame(fd, acc, kTimeoutMs)) {
            SocketUtils::closeSocket(fd);
            *outResult = result;
            return;
        }

        if (acc.frameKind() != FrameAccumulator::FrameKind::Ack) {
            SocketUtils::closeSocket(fd);
            *outResult = result;
            return;
        }

        TransportCodec::ParsedAckPayload parsed;
        if (!TransportCodec::parseAckPayload(acc.payload(), acc.payloadLen(), parsed)) {
            SocketUtils::closeSocket(fd);
            *outResult = result;
            return;
        }

        result.ok = true;
        result.gotAck = true;
        result.ack = parsed;

        SocketUtils::closeSocket(fd);
        *outResult = result;
        return;
    }

    std::vector<uint8_t> frame;

    if (mode == ClientMode::SendValidData) {
        const MACAddress src = makeMac(1, 2, 3, 4, 5, 6);
        const MACAddress dst = makeMac(10, 11, 12, 13, 14, 15);
        const uint8_t payload[] = {0xAA, 0xBB, 0xCC};

        if (!TransportCodec::buildDataFrame(frame, src, dst, seq, payload, sizeof(payload))) {
            SocketUtils::closeSocket(fd);
            *outResult = result;
            return;
        }
    } else if (mode == ClientMode::SendAckFrame) {
        if (!TransportCodec::buildAckFrame(frame, seq, TransportCodec::AckCode::Ok, 0)) {
            SocketUtils::closeSocket(fd);
            *outResult = result;
            return;
        }
    } else if (mode == ClientMode::SendInvalidFrame) {
        frame = {9, 0, 1, 0, 0x42};
    }

    result.ok = SocketUtils::writeExact(fd,
                                        frame.data(),
                                        static_cast<uint16_t>(frame.size()),
                                        kTimeoutMs);

    SocketUtils::closeSocket(fd);
    *outResult = result;
}

bool testReceiveValidData() {
    SocketServer server;
    if (!server.begin(kPort)) return false;

    const uint16_t seq = 0x1234;
    ClientResult clientResult{};
    std::thread t(clientWorker, ClientMode::SendValidData, seq, &clientResult);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        t.join();
        return false;
    }

    InboundConnection::ReceivedData data;
    const auto rc = InboundConnection::receiveOne(conn, data, kTimeoutMs);

    t.join();

    if (rc != InboundConnection::ReceiveResult::Ok) return false;
    if (!clientResult.ok) return false;
    if (data.seq != seq) return false;
    if (data.payload.size() != 3) return false;
    if (data.payload.empty()) return false;
    return data.payload[0] == 0xAA &&
           data.payload[1] == 0xBB &&
           data.payload[2] == 0xCC;
}

bool testReceiveRejectsAckFrame() {
    SocketServer server;
    if (!server.begin(kPort)) return false;

    const uint16_t seq = 0x2222;
    ClientResult clientResult{};
    std::thread t(clientWorker, ClientMode::SendAckFrame, seq, &clientResult);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        t.join();
        return false;
    }

    InboundConnection::ReceivedData data;
    const auto rc = InboundConnection::receiveOne(conn, data, kTimeoutMs);

    t.join();

    return clientResult.ok &&
           rc == InboundConnection::ReceiveResult::NotDataFrame;
}

bool testReceiveRejectsInvalidFrame() {
    SocketServer server;
    if (!server.begin(kPort)) return false;

    const uint16_t seq = 0;
    ClientResult clientResult{};
    std::thread t(clientWorker, ClientMode::SendInvalidFrame, seq, &clientResult);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        t.join();
        return false;
    }

    InboundConnection::ReceivedData data;
    const auto rc = InboundConnection::receiveOne(conn, data, kTimeoutMs);

    t.join();

    return clientResult.ok &&
           rc == InboundConnection::ReceiveResult::InvalidFrame;
}

bool testSendAck() {
    SocketServer server;
    if (!server.begin(kPort)) return false;

    const uint16_t seq = 0xBEEF;
    ClientResult clientResult{};
    std::thread t(clientWorker, ClientMode::ReceiveAckOnly, seq, &clientResult);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    auto conn = server.accept(kTimeoutMs);
    if (!conn.isValid()) {
        t.join();
        return false;
    }

    const auto rc = InboundConnection::sendAck(conn,
                                               seq,
                                               TransportCodec::AckCode::QueueFull,
                                               kTimeoutMs,
                                               0x5A);

    t.join();

    return rc == InboundConnection::AckResult::Ok &&
           clientResult.ok &&
           clientResult.gotAck &&
           clientResult.ack.seq == seq &&
           clientResult.ack.code == TransportCodec::AckCode::QueueFull &&
           clientResult.ack.flags == 0x5A;
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

    if (!runTest("receive_valid_data", testReceiveValidData)) ++fails;
    if (!runTest("receive_rejects_ack_frame", testReceiveRejectsAckFrame)) ++fails;
    if (!runTest("receive_rejects_invalid_frame", testReceiveRejectsInvalidFrame)) ++fails;
    if (!runTest("send_ack", testSendAck)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all InboundConnection tests passed\n";
    return 0;
}