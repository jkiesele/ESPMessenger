// c++ -std=c++17 -Wall -Wextra -pedantic -pthread  SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp OutboundTransaction.cpp PlatformThreads.cpp  PlatformMutex.cpp TCPTransport.cpp MessengerCodec.cpp TCPMessenger.cpp  EncryptionHandler.cpp test_tcp_messenger_failures_0.cpp  -o test_tcp_messenger_failures_0

#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "TCPMessenger.h"
#include "TCPTransport.h"
#include "SocketServer.h"
#include "SocketUtils.h"
#include "TransportCodec.h"
#include "MessengerCodec.h"
#include "FrameAccumulator.h"
#include "Helpers.h"
#include "EncryptionHandler.h"
#include "Serializable.h"

using tcpmsg::TCPMessenger;
using tcpmsg::TCPTransport;
using tcpmsg::SocketServer;
using tcpmsg::SocketUtils;
using tcpmsg::TransportCodec;
using tcpmsg::MessengerCodec;
using tcpmsg::FrameAccumulator;
using tcpmsg::MACAddress;

namespace {

constexpr uint16_t kPortA = 12445;
constexpr uint16_t kPortB = 12446;
constexpr uint32_t kPollSleepMs = 20;
constexpr uint32_t kWaitMs = 5000;

const IPAddress kLocalIp(127, 0, 0, 1);

MACAddress makeMac(uint8_t a0, uint8_t a1, uint8_t a2,
                   uint8_t a3, uint8_t a4, uint8_t a5) {
    const uint8_t raw[6] = {a0, a1, a2, a3, a4, a5};
    return MACAddress(raw);
}

class TestMessage : public Serializable {
public:
    uint8_t valueA = 0;
    uint16_t valueB = 0;
    std::vector<uint8_t> blob;

    uint8_t typeId() const override {
        return 42;
    }

    uint16_t payloadSize() const override {
        return static_cast<uint16_t>(1 + 2 + 2 + blob.size());
    }

    void serializeTo(uint8_t* dst) const override {
        dst[0] = valueA;
        dst[1] = static_cast<uint8_t>(valueB & 0xFF);
        dst[2] = static_cast<uint8_t>((valueB >> 8) & 0xFF);

        const uint16_t n = static_cast<uint16_t>(blob.size());
        dst[3] = static_cast<uint8_t>(n & 0xFF);
        dst[4] = static_cast<uint8_t>((n >> 8) & 0xFF);

        for (uint16_t i = 0; i < n; ++i) {
            dst[5 + i] = blob[i];
        }
    }

    bool fromBuffer(const uint8_t* src, uint16_t len) override {
        if (!src || len < 5) return false;

        valueA = src[0];
        valueB = static_cast<uint16_t>(src[1]) |
                 (static_cast<uint16_t>(src[2]) << 8);

        const uint16_t n = static_cast<uint16_t>(src[3]) |
                           (static_cast<uint16_t>(src[4]) << 8);

        if (len != static_cast<uint16_t>(5 + n)) return false;

        blob.resize(n);
        for (uint16_t i = 0; i < n; ++i) {
            blob[i] = src[5 + i];
        }
        return true;
    }

    bool operator==(const TestMessage& o) const {
        return valueA == o.valueA &&
               valueB == o.valueB &&
               blob == o.blob;
    }
};

bool waitForSendResult(TCPMessenger& m,
                       TCPMessenger::SendResult& out,
                       uint32_t timeoutMs) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (std::chrono::steady_clock::now() < deadline) {
        if (m.popSendResult(out)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollSleepMs));
    }
    return false;
}

bool waitForReceived(TCPMessenger& m,
                     TCPMessenger::ReceivedMessage& out,
                     TCPMessenger::Result& rc,
                     uint32_t timeoutMs) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (std::chrono::steady_clock::now() < deadline) {
        if (m.popReceivedMessage(out, rc)) {
            return true;
        }
        if (rc != TCPMessenger::Result::NoMessage) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollSleepMs));
    }

    rc = TCPMessenger::Result::NoMessage;
    return false;
}

bool waitForReceiveFailure(TCPMessenger& m,
                           TCPMessenger::Result expected,
                           uint32_t timeoutMs) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (std::chrono::steady_clock::now() < deadline) {
        TCPMessenger::ReceivedMessage tmp;
        TCPMessenger::Result rc = TCPMessenger::Result::NoMessage;
        if (m.popReceivedMessage(tmp, rc)) {
            return false;
        }
        if (rc == expected) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollSleepMs));
    }
    return false;
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

void rawClientSendTransportPayload(const IPAddress& ip,
                                   uint16_t port,
                                   const MACAddress& srcMac,
                                   const MACAddress& dstMac,
                                   uint16_t seq,
                                   const std::vector<uint8_t>& transportPayload,
                                   bool* outOk) {
    *outOk = false;

    std::vector<uint8_t> frame;
    if (!TransportCodec::buildDataFrame(frame,
                                        srcMac,
                                        dstMac,
                                        seq,
                                        transportPayload.empty() ? nullptr : transportPayload.data(),
                                        static_cast<uint16_t>(transportPayload.size()))) {
        return;
    }

    int fd = SocketUtils::connectTo(ip, port, 1000);
    if (fd < 0) return;

    if (!SocketUtils::writeExact(fd,
                                 frame.data(),
                                 static_cast<uint16_t>(frame.size()),
                                 1000)) {
        SocketUtils::closeSocket(fd);
        return;
    }

    FrameAccumulator acc;
    while (!acc.complete() && !acc.invalid()) {
        uint8_t byte = 0;
        if (!SocketUtils::readExact(fd, &byte, 1, 1000)) {
            SocketUtils::closeSocket(fd);
            return;
        }
        acc.feed(byte);
    }

    if (!acc.invalid() && acc.frameKind() == FrameAccumulator::FrameKind::Ack) {
        TransportCodec::ParsedAckPayload ack;
        if (TransportCodec::parseAckPayload(acc.payload(), acc.payloadLen(), ack) &&
            ack.code == TransportCodec::AckCode::Ok) {
            *outOk = true;
        }
    }

    SocketUtils::closeSocket(fd);
}

enum class RawPeerMode : uint8_t {
    AckOk,
    NeverStart
};

bool testDecryptFailed() {
    const std::vector<uint32_t> keysA = {0x11111111u, 0x22222222u};
    const std::vector<uint32_t> keysB = {0xAAAAAAAAu, 0xBBBBBBBBu};

    EncryptionHandler encA(&keysA);
    EncryptionHandler encB(&keysB);

    TCPMessenger a;
    TCPMessenger b;

    const MACAddress macA = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress macB = makeMac(10, 11, 12, 13, 14, 15);

    if (!a.begin(kPortA, macA, &encA)) return false;
    if (!b.begin(kPortB, macB, &encB)) {
        a.end();
        return false;
    }

    TestMessage msg;
    msg.valueA = 7;
    msg.valueB = 0x1234;
    msg.blob = {1, 2, 3, 4};

    TCPMessenger::SendOptions opt;
    opt.timeoutMs = 300;
    opt.maxRetries = 3;
    opt.retryDelayMs = 50;

    if (a.sendToIP(msg, 5, kLocalIp, kPortB, macB, opt) != TCPMessenger::Result::Ok) {
        a.end();
        b.end();
        return false;
    }

    TCPMessenger::SendResult sr;
    const bool gotSend = waitForSendResult(a, sr, kWaitMs);
    const bool gotDecryptFailure = waitForReceiveFailure(b, TCPMessenger::Result::DecryptFailed, kWaitMs);

    a.end();
    b.end();

    return gotSend && sr.rc == TCPMessenger::Result::Ok && gotDecryptFailure;
}

bool testInvalidEnvelope() {
    const std::vector<uint32_t> keys = {0x12345678u, 0xCAFEBABEu};
    EncryptionHandler enc(&keys);

    TCPMessenger b;
    const MACAddress macSrc = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress macB   = makeMac(10, 11, 12, 13, 14, 15);

    if (!b.begin(kPortB, macB, &enc)) return false;

    // Invalid messenger payload: embedded len says 4, actual bytes follow only 2.
    const std::vector<uint8_t> badMessengerPayload = {
        42, 9, 4, 0, 0xAA, 0xBB
    };

    bool sendOk = false;
    std::thread t(rawClientSendTransportPayload,
                  kLocalIp,
                  kPortB,
                  macSrc,
                  macB,
                  0x1111,
                  badMessengerPayload,
                  &sendOk);
    t.join();

    const bool gotInvalidEnvelope =
        waitForReceiveFailure(b, TCPMessenger::Result::InvalidEnvelope, kWaitMs);

    b.end();
    return sendOk && gotInvalidEnvelope;
}

bool testRetryLimitReached() {
    const std::vector<uint32_t> keys = {0x89ABCDEFu, 0x10203040u};
    EncryptionHandler encA(&keys);

    TCPMessenger a;
    const MACAddress macA = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress macB = makeMac(10, 11, 12, 13, 14, 15);

    if (!a.begin(kPortA, macA, &encA)) return false;

    TestMessage msg;
    msg.valueA = 9;
    msg.valueB = 0xBEEF;
    msg.blob = {0x10, 0x20};

    TCPMessenger::SendOptions opt;
    opt.timeoutMs = 150;
    opt.maxRetries = 3;
    opt.retryDelayMs = 50;

    const auto queueRc = a.sendToIP(msg, 3, kLocalIp, kPortB, macB, opt);
    if (queueRc != TCPMessenger::Result::Ok) {
        a.end();
        return false;
    }

    TCPMessenger::SendResult sr;
    const bool got = waitForSendResult(a, sr, kWaitMs);

    a.end();

    return got && sr.rc == TCPMessenger::Result::RetryLimitReached;
}

bool testDuplicateOnlyOnce() {
    const std::vector<uint32_t> keys = {0x22222222u, 0x33333333u};
    EncryptionHandler enc(&keys);

    TCPMessenger b;
    const MACAddress macSrc = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress macB   = makeMac(10, 11, 12, 13, 14, 15);

    if (!b.begin(kPortB, macB, &enc)) return false;

    TestMessage msg;
    msg.valueA = 4;
    msg.valueB = 0x0102;
    msg.blob = {0xAA, 0xBB};

    std::vector<uint8_t> plaintext(msg.payloadSize());
    msg.serializeTo(plaintext.data());

    EncryptionHandler encSender(&keys);
    const std::vector<uint8_t> encrypted = encSender.encrypt(plaintext);

    std::vector<uint8_t> messengerPayload;
    if (!MessengerCodec::buildMessage(messengerPayload,
                                      msg.typeId(),
                                      8,
                                      encrypted.data(),
                                      static_cast<uint16_t>(encrypted.size()))) {
        b.end();
        return false;
    }

    bool ok1 = false;
    bool ok2 = false;

    std::thread t1(rawClientSendTransportPayload,
                   kLocalIp, kPortB, macSrc, macB, 0x2222, messengerPayload, &ok1);
    t1.join();

    std::thread t2(rawClientSendTransportPayload,
                   kLocalIp, kPortB, macSrc, macB, 0x2222, messengerPayload, &ok2);
    t2.join();

    int gotCount = 0;
    TCPMessenger::ReceivedMessage rx;
    TCPMessenger::Result rc = TCPMessenger::Result::NoMessage;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(kWaitMs);

    while (std::chrono::steady_clock::now() < deadline) {
        if (b.popReceivedMessage(rx, rc)) {
            ++gotCount;
        } else if (rc != TCPMessenger::Result::NoMessage) {
            b.end();
            return false;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(kPollSleepMs));
        }
    }

    b.end();
    return ok1 && ok2 && gotCount == 1;
}

bool testLargePayloadRoundtrip() {
    const std::vector<uint32_t> keys = {0x12341234u, 0xABCDABCDu};
    EncryptionHandler encA(&keys);
    EncryptionHandler encB(&keys);

    TCPMessenger a;
    TCPMessenger b;

    const MACAddress macA = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress macB = makeMac(10, 11, 12, 13, 14, 15);

    if (!a.begin(kPortA, macA, &encA)) return false;
    if (!b.begin(kPortB, macB, &encB)) {
        a.end();
        return false;
    }

    TestMessage msgOut;
    msgOut.valueA = 0x55;
    msgOut.valueB = 0x6677;

    // Stay comfortably below the total frame limit after messenger header + encryption overhead.
    msgOut.blob.resize(180);
    for (size_t i = 0; i < msgOut.blob.size(); ++i) {
        msgOut.blob[i] = static_cast<uint8_t>(i & 0xFF);
    }

    TCPMessenger::SendOptions opt;
    opt.timeoutMs = 300;
    opt.maxRetries = 3;
    opt.retryDelayMs = 50;

    const auto qrc = a.sendToIP(msgOut, 12, kLocalIp, kPortB, macB, opt);
    if (qrc != TCPMessenger::Result::Ok) {
        a.end();
        b.end();
        return false;
    }

    TCPMessenger::SendResult sr;
    if (!waitForSendResult(a, sr, kWaitMs)) {
        a.end();
        b.end();
        return false;
    }

    TCPMessenger::ReceivedMessage rx;
    TCPMessenger::Result rc = TCPMessenger::Result::NoMessage;
    if (!waitForReceived(b, rx, rc, kWaitMs)) {
        a.end();
        b.end();
        return false;
    }

    TestMessage msgIn;
    const bool decodeOk = msgIn.fromBuffer(rx.payload.data(),
                                           static_cast<uint16_t>(rx.payload.size()));

    a.end();
    b.end();

    return sr.rc == TCPMessenger::Result::Ok &&
           decodeOk &&
           rx.type == msgOut.typeId() &&
           rx.chanId == 12 &&
           msgIn == msgOut;
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

    if (!runTest("decrypt_failed", testDecryptFailed)) ++fails;
    if (!runTest("invalid_envelope", testInvalidEnvelope)) ++fails;
    if (!runTest("retry_limit_reached", testRetryLimitReached)) ++fails;
    if (!runTest("duplicate_only_once", testDuplicateOnlyOnce)) ++fails;
    if (!runTest("large_payload_roundtrip", testLargePayloadRoundtrip)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all advanced TCPMessenger tests passed\n";
    return 0;
}