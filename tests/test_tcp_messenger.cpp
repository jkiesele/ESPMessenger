// c++ -std=c++17 -Wall -Wextra -pedantic -pthread SocketUtils.cpp SocketServer.cpp FrameAccumulator.cpp TransportCodec.cpp InboundConnection.cpp OutboundTransaction.cpp PlatformThreads.cpp  PlatformMutex.cpp TCPTransport.cpp MessengerCodec.cpp TCPMessenger.cpp  EncryptionHandler.cpp test_tcp_messenger.cpp -o test_tcp_messenger

#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "TCPMessenger.h"
#include "EncryptionHandler.h"
#include "Serializable.h"

using tcpmsg::TCPMessenger;
using tcpmsg::MACAddress;

namespace {

constexpr uint16_t kPortA = 12345;
constexpr uint16_t kPortB = 12346;
constexpr uint32_t kPollSleepMs = 20;
constexpr uint32_t kWaitMs = 4000;

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
        if (!src) return false;
        if (len < 5) return false;

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

bool testSendReceiveOk() {
    const std::vector<uint32_t> keys = {0x12345678u, 0xCAFEBABEu};
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
    msgOut.valueA = 7;
    msgOut.valueB = 0x1234;
    msgOut.blob = {0xAA, 0xBB, 0xCC, 0xDD};

    TCPMessenger::SendOptions opt;
    opt.timeoutMs = 300;
    opt.maxRetries = 3;
    opt.retryDelayMs = 50;

    const auto queueRc = a.sendToIP(msgOut, 9, kLocalIp, kPortB, macB, opt);
    if (queueRc != TCPMessenger::Result::Ok) {
        a.end();
        b.end();
        return false;
    }

    TCPMessenger::SendResult sendRes;
    if (!waitForSendResult(a, sendRes, kWaitMs)) {
        a.end();
        b.end();
        return false;
    }

    if (sendRes.rc != TCPMessenger::Result::Ok) {
        a.end();
        b.end();
        return false;
    }

    TCPMessenger::ReceivedMessage rx;
    TCPMessenger::Result rxRc = TCPMessenger::Result::NoMessage;
    if (!waitForReceived(b, rx, rxRc, kWaitMs)) {
        a.end();
        b.end();
        return false;
    }

    TestMessage msgIn;
    const bool decodeOk = msgIn.fromBuffer(rx.payload.data(),
                                           static_cast<uint16_t>(rx.payload.size()));

    a.end();
    b.end();

    return decodeOk &&
           rx.type == msgOut.typeId() &&
           rx.chanId == 9 &&
           rx.srcMac == macA &&
           rx.dstMac == macB &&
           msgIn == msgOut;
}

bool testBusyRejectsSecondSend() {
    const std::vector<uint32_t> keys = {0x11111111u, 0x22222222u};
    EncryptionHandler encA(&keys);

    TCPMessenger a;
    const MACAddress macA = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress macB = makeMac(10, 11, 12, 13, 14, 15);

    if (!a.begin(kPortA, macA, &encA)) return false;

    TestMessage msg;
    msg.valueA = 1;
    msg.valueB = 2;
    msg.blob = {3, 4, 5};

    TCPMessenger::SendOptions opt;
    opt.timeoutMs = 500;
    opt.maxRetries = 3;
    opt.retryDelayMs = 100;

    const auto rc1 = a.sendToIP(msg, 1, kLocalIp, kPortB, macB, opt);
    const auto rc2 = a.sendToIP(msg, 1, kLocalIp, kPortB, macB, opt);

    TCPMessenger::SendResult sr;
    waitForSendResult(a, sr, kWaitMs);
    a.end();

    return rc1 == TCPMessenger::Result::Ok &&
           rc2 == TCPMessenger::Result::Busy;
}

bool testRetryLaterSuccess() {
    const std::vector<uint32_t> keys = {0x89ABCDEFu, 0x10203040u};
    EncryptionHandler encA(&keys);
    EncryptionHandler encB(&keys);

    TCPMessenger a;
    TCPMessenger b;

    const MACAddress macA = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress macB = makeMac(10, 11, 12, 13, 14, 15);

    if (!a.begin(kPortA, macA, &encA)) return false;

    TestMessage msgOut;
    msgOut.valueA = 9;
    msgOut.valueB = 0xBEEF;
    msgOut.blob = {0x10, 0x20};

    TCPMessenger::SendOptions opt;
    opt.timeoutMs = 200;
    opt.maxRetries = 3;
    opt.retryDelayMs = 150;

    const auto queueRc = a.sendToIP(msgOut, 3, kLocalIp, kPortB, macB, opt);
    if (queueRc != TCPMessenger::Result::Ok) {
        a.end();
        return false;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(320));

    if (!b.begin(kPortB, macB, &encB)) {
        a.end();
        return false;
    }

    TCPMessenger::SendResult sendRes;
    if (!waitForSendResult(a, sendRes, kWaitMs)) {
        a.end();
        b.end();
        return false;
    }

    TCPMessenger::ReceivedMessage rx;
    TCPMessenger::Result rxRc = TCPMessenger::Result::NoMessage;
    const bool gotRx = waitForReceived(b, rx, rxRc, kWaitMs);

    TestMessage msgIn;
    const bool decodeOk = gotRx &&
                          msgIn.fromBuffer(rx.payload.data(),
                                           static_cast<uint16_t>(rx.payload.size()));

    a.end();
    b.end();

    return sendRes.rc == TCPMessenger::Result::Ok &&
           gotRx &&
           decodeOk &&
           rx.type == msgOut.typeId() &&
           rx.chanId == 3 &&
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

    if (!runTest("send_receive_ok", testSendReceiveOk)) ++fails;
    if (!runTest("busy_rejects_second_send", testBusyRejectsSecondSend)) ++fails;
    if (!runTest("retry_later_success", testRetryLaterSuccess)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all TCPMessenger tests passed\n";
    return 0;
}