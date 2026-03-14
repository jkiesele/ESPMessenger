// c++ -std=c++17 -Wall -Wextra -pedantic -pthread SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp OutboundTransaction.cpp test_outbound_transaction.cpp -o test_outbound_transaction

#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "Config.h"
#include "FrameAccumulator.h"
#include "Helpers.h"
#include "OutboundTransaction.h"
#include "SocketServer.h"
#include "TransportCodec.h"

using tcpmsg::FrameAccumulator;
using tcpmsg::MACAddress;
using tcpmsg::OutboundTransaction;
using tcpmsg::SocketServer;
using tcpmsg::TransportCodec;

namespace {

constexpr uint16_t kPort = 12345;
constexpr uint32_t kTimeoutMs = 2000;
const IPAddress kIp(127, 0, 0, 1);

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

enum class ServerMode : uint8_t {
    AckOk,
    AckWrongSeq,
    AckWrongDestination,
    AckQueueFull,
    AckTransportError,
    AckInvalidFrame,
    CloseEarly,
    NoReply
};

struct ServerResult {
    bool ok = false;
    bool gotDataFrame = false;
    bool dataPayloadParsed = false;
};

void serverWorker(ServerMode mode,
                  uint16_t expectedSeq,
                  ServerResult* outResult) {
    ServerResult result{};

    SocketServer server;
    if (!server.begin(kPort)) {
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

    result.gotDataFrame = (acc.frameKind() == FrameAccumulator::FrameKind::Data);

    TransportCodec::ParsedDataPayload parsedData;
    result.dataPayloadParsed =
        result.gotDataFrame &&
        TransportCodec::parseDataPayload(acc.payload(), acc.payloadLen(), parsedData);

    if (mode == ServerMode::CloseEarly) {
        conn.close();
        result.ok = true;
        *outResult = result;
        return;
    }

    if (mode == ServerMode::NoReply) {
        std::this_thread::sleep_for(std::chrono::milliseconds(kTimeoutMs + 500));
        result.ok = true;
        *outResult = result;
        return;
    }

    if (mode == ServerMode::AckInvalidFrame) {
        const uint8_t badFrame[] = {
            9, 0, 1, 0, 0x42
        };
        result.ok = conn.writeExact(badFrame, sizeof(badFrame), kTimeoutMs);
        *outResult = result;
        return;
    }

    uint16_t ackSeq = expectedSeq;
    TransportCodec::AckCode ackCode = TransportCodec::AckCode::Ok;

    switch (mode) {
        case ServerMode::AckOk:
            ackCode = TransportCodec::AckCode::Ok;
            break;
        case ServerMode::AckWrongSeq:
            ackSeq = static_cast<uint16_t>(expectedSeq + 1);
            ackCode = TransportCodec::AckCode::Ok;
            break;
        case ServerMode::AckWrongDestination:
            ackCode = TransportCodec::AckCode::WrongDestination;
            break;
        case ServerMode::AckQueueFull:
            ackCode = TransportCodec::AckCode::QueueFull;
            break;
        case ServerMode::AckTransportError:
            ackCode = TransportCodec::AckCode::TransportError;
            break;
        default:
            *outResult = result;
            return;
    }

    std::vector<uint8_t> ackFrame;
    if (!TransportCodec::buildAckFrame(ackFrame, ackSeq, ackCode, 0)) {
        *outResult = result;
        return;
    }

    result.ok = conn.writeExact(ackFrame.data(),
                                static_cast<uint16_t>(ackFrame.size()),
                                kTimeoutMs);
    *outResult = result;
}

bool runCase(const char* name,
             ServerMode mode,
             OutboundTransaction::Result expectedTxResult) {
    std::cout << "[RUN ] " << name << "\n";

    const MACAddress src = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress dst = makeMac(10, 11, 12, 13, 14, 15);
    const uint16_t seq = 0x1234;
    const uint8_t payload[] = {0xAA, 0xBB, 0xCC};

    std::vector<uint8_t> frame;
    if (!TransportCodec::buildDataFrame(frame, src, dst, seq, payload, sizeof(payload))) {
        std::cout << "[FAIL] " << name << " (could not build DATA frame)\n";
        return false;
    }

    ServerResult serverResult{};
    std::thread serverThread(serverWorker, mode, seq, &serverResult);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    const auto txResult = OutboundTransaction::run(kIp,
                                                   kPort,
                                                   frame.data(),
                                                   static_cast<uint16_t>(frame.size()),
                                                   seq,
                                                   kTimeoutMs);

    serverThread.join();

    const bool ok =
        (txResult == expectedTxResult) &&
        serverResult.ok &&
        serverResult.gotDataFrame &&
        serverResult.dataPayloadParsed;

    std::cout << (ok ? "[ OK ] " : "[FAIL] ") << name << "\n";
    return ok;
}

bool testAckOk() {
    return runCase("ack_ok",
                   ServerMode::AckOk,
                   OutboundTransaction::Result::Ok);
}

bool testAckWrongSeq() {
    return runCase("ack_wrong_seq",
                   ServerMode::AckWrongSeq,
                   OutboundTransaction::Result::AckWrongSequence);
}

bool testAckWrongDestination() {
    return runCase("ack_wrong_destination",
                   ServerMode::AckWrongDestination,
                   OutboundTransaction::Result::AckWrongDestination);
}

bool testAckQueueFull() {
    return runCase("ack_queue_full",
                   ServerMode::AckQueueFull,
                   OutboundTransaction::Result::AckQueueFull);
}

bool testAckTransportError() {
    return runCase("ack_transport_error",
                   ServerMode::AckTransportError,
                   OutboundTransaction::Result::AckTransportError);
}

bool testAckInvalidFrame() {
    return runCase("ack_invalid_frame",
                   ServerMode::AckInvalidFrame,
                   OutboundTransaction::Result::AckInvalid);
}

bool testCloseEarly() {
    return runCase("close_early",
                   ServerMode::CloseEarly,
                   OutboundTransaction::Result::ReadFailed);
}

bool testNoReply() {
    return runCase("no_reply",
                   ServerMode::NoReply,
                   OutboundTransaction::Result::ReadFailed);
}

using TestFn = bool(*)();

bool runTest(const char* name, TestFn fn) {
    return fn();
}

} // namespace

int main() {
    int fails = 0;

    if (!runTest("ack_ok", testAckOk)) ++fails;
    if (!runTest("ack_wrong_seq", testAckWrongSeq)) ++fails;
    if (!runTest("ack_wrong_destination", testAckWrongDestination)) ++fails;
    if (!runTest("ack_queue_full", testAckQueueFull)) ++fails;
    if (!runTest("ack_transport_error", testAckTransportError)) ++fails;
    if (!runTest("ack_invalid_frame", testAckInvalidFrame)) ++fails;
    if (!runTest("close_early", testCloseEarly)) ++fails;
    if (!runTest("no_reply", testNoReply)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all OutboundTransaction tests passed\n";
    return 0;
}