#include <cstdint>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

#include "PlatformThreads.h"
#include "TCPTransport.h"
#include "TCPMessenger.h"
#include "EncryptionHandler.h"
#include "Serializable.h"

using tcpmsg::PlatformThread;
using tcpmsg::TCPTransport;
using tcpmsg::TCPMessenger;
using tcpmsg::MACAddress;

namespace {

constexpr uint16_t kPortA = 12545;
constexpr uint16_t kPortB = 12546;
constexpr uint32_t kWaitMs = 3000;
constexpr uint32_t kPollSleepMs = 20;

const IPAddress kLocalIp(127, 0, 0, 1);

MACAddress makeMac(uint8_t a0, uint8_t a1, uint8_t a2,
                   uint8_t a3, uint8_t a4, uint8_t a5) {
    const uint8_t raw[6] = {a0, a1, a2, a3, a4, a5};
    return MACAddress(raw);
}

class TinyMessage : public Serializable {
public:
    uint8_t v = 0;

    uint8_t typeId() const override {
        return 7;
    }

    uint16_t payloadSize() const override {
        return 1;
    }

    void serializeTo(uint8_t* dst) const override {
        dst[0] = v;
    }

    bool fromBuffer(const uint8_t* src, uint16_t len) override {
        if (!src || len != 1) return false;
        v = src[0];
        return true;
    }
};

struct ThreadCtx {
    int counter = 0;
};

void threadWorker(void* ctxPtr) {
    auto* ctx = static_cast<ThreadCtx*>(ctxPtr);
    ++ctx->counter;
    PlatformThread::sleepMs(50);
}

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

bool testPlatformThreadRestart() {
    PlatformThread t;
    ThreadCtx ctx;

    if (!t.start(&threadWorker, &ctx, "thr1", 4096)) return false;
    if (!t.waitUntilStopped(1000)) return false;
    if (ctx.counter != 1) return false;

    if (!t.start(&threadWorker, &ctx, "thr2", 4096)) return false;
    if (!t.waitUntilStopped(1000)) return false;
    if (ctx.counter != 2) return false;

    return true;
}

bool testTCPTransportRestart() {
    TCPTransport t;
    const MACAddress mac = makeMac(1, 2, 3, 4, 5, 6);

    if (!t.begin(kPortA, mac)) return false;
    if (!t.isRunning()) return false;
    t.end();
    if (t.isRunning()) return false;

    if (!t.begin(kPortA, mac)) return false;
    if (!t.isRunning()) return false;
    t.end();
    if (t.isRunning()) return false;

    return true;
}

bool testTCPTransportDoubleBegin() {
    TCPTransport t;
    const MACAddress mac = makeMac(1, 2, 3, 4, 5, 6);

    if (!t.begin(kPortA, mac)) return false;
    if (!t.isRunning()) return false;

    // begin() internally calls end(), so this should still work.
    if (!t.begin(kPortA, mac)) return false;
    if (!t.isRunning()) return false;

    t.end();
    return !t.isRunning();
}

bool testTCPTransportEndWithoutBegin() {
    TCPTransport t;
    t.end();
    return !t.isRunning();
}

bool testTCPMessengerRestart() {
    const std::vector<uint32_t> keys = {0x12345678u, 0xCAFEBABEu};
    EncryptionHandler enc(&keys);

    TCPMessenger m;
    const MACAddress mac = makeMac(1, 2, 3, 4, 5, 6);

    if (!m.begin(kPortA, mac, &enc)) return false;
    if (!m.isRunning()) return false;
    m.end();
    if (m.isRunning()) return false;

    if (!m.begin(kPortA, mac, &enc)) return false;
    if (!m.isRunning()) return false;
    m.end();
    if (m.isRunning()) return false;

    return true;
}

bool testTCPMessengerDoubleBegin() {
    const std::vector<uint32_t> keys = {0x11111111u, 0x22222222u};
    EncryptionHandler enc(&keys);

    TCPMessenger m;
    const MACAddress mac = makeMac(1, 2, 3, 4, 5, 6);

    if (!m.begin(kPortA, mac, &enc)) return false;
    if (!m.isRunning()) return false;

    if (!m.begin(kPortA, mac, &enc)) return false;
    if (!m.isRunning()) return false;

    m.end();
    return !m.isRunning();
}

bool testTCPMessengerEndWithoutBegin() {
    TCPMessenger m;
    m.end();
    return !m.isRunning();
}

bool testTCPMessengerWorksAfterRestart() {
    const std::vector<uint32_t> keys = {0x89ABCDEFu, 0x10203040u};
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

    a.end();
    b.end();

    if (!a.begin(kPortA, macA, &encA)) return false;
    if (!b.begin(kPortB, macB, &encB)) {
        a.end();
        return false;
    }

    TinyMessage outMsg;
    outMsg.v = 0x5A;

    TCPMessenger::SendOptions opt;
    opt.timeoutMs = 200;
    opt.maxRetries = 1;
    opt.retryDelayMs = 20;

    if (a.sendToIP(outMsg, 3, kLocalIp, kPortB, macB, opt) != TCPMessenger::Result::Ok) {
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

    TinyMessage inMsg;
    const bool decodeOk = inMsg.fromBuffer(rx.payload.data(),
                                           static_cast<uint16_t>(rx.payload.size()));

    a.end();
    b.end();

    return sr.rc == TCPMessenger::Result::Ok &&
           decodeOk &&
           rx.type == outMsg.typeId() &&
           rx.chanId == 3 &&
           inMsg.v == outMsg.v;
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

    if (!runTest("platform_thread_restart", testPlatformThreadRestart)) ++fails;
    if (!runTest("tcp_transport_restart", testTCPTransportRestart)) ++fails;
    if (!runTest("tcp_transport_double_begin", testTCPTransportDoubleBegin)) ++fails;
    if (!runTest("tcp_transport_end_without_begin", testTCPTransportEndWithoutBegin)) ++fails;
    if (!runTest("tcp_messenger_restart", testTCPMessengerRestart)) ++fails;
    if (!runTest("tcp_messenger_double_begin", testTCPMessengerDoubleBegin)) ++fails;
    if (!runTest("tcp_messenger_end_without_begin", testTCPMessengerEndWithoutBegin)) ++fails;
    if (!runTest("tcp_messenger_works_after_restart", testTCPMessengerWorksAfterRestart)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all restart/lifecycle tests passed\n";
    return 0;
}