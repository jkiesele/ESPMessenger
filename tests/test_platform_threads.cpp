// c++ -std=c++17 -Wall -Wextra -pedantic -pthread PlatformThreads.cpp test_platform_threads.cpp  -o test_platform_threads

#include <cstdint>
#include <iostream>
#include <atomic>

#include "PlatformThreads.h"

namespace {

struct CounterContext {
    std::atomic<int> counter{0};
    std::atomic<bool> entered{false};
};

void workerIncrement(void* ctxPtr) {
    auto* ctx = static_cast<CounterContext*>(ctxPtr);
    ctx->entered.store(true);
    for (int i = 0; i < 20; ++i) {
        ++ctx->counter;
        tcpmsg::PlatformThread::sleepMs(10);
    }
}

void workerSleep(void*) {
    tcpmsg::PlatformThread::sleepMs(200);
}

bool testStartAndStop() {
    CounterContext ctx;
    tcpmsg::PlatformThread t;

    if (!t.start(&workerIncrement, &ctx, "test_inc", 4096)) {
        return false;
    }

    if (!t.waitUntilStopped(1000)) {
        return false;
    }

    return ctx.entered.load() && ctx.counter.load() == 20 && !t.isRunning();
}

bool testDoubleStartRejected() {
    CounterContext ctx;
    tcpmsg::PlatformThread t;

    if (!t.start(&workerSleep, &ctx, "test_once", 4096)) {
        return false;
    }

    const bool secondStart = t.start(&workerSleep, &ctx, "test_twice", 4096);
    const bool stopped = t.waitUntilStopped(1000);

    return !secondStart && stopped;
}

bool testWaitTimeout() {
    CounterContext ctx;
    tcpmsg::PlatformThread t;

    if (!t.start(&workerSleep, &ctx, "test_timeout", 4096)) {
        return false;
    }

    const bool earlyStop = t.waitUntilStopped(20);
    const bool finalStop = t.waitUntilStopped(1000);

    return !earlyStop && finalStop;
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

    if (!runTest("start_and_stop", testStartAndStop)) ++fails;
    if (!runTest("double_start_rejected", testDoubleStartRejected)) ++fails;
    if (!runTest("wait_timeout", testWaitTimeout)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all PlatformThread tests passed\n";
    return 0;
}