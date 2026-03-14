// c++ -std=c++17 -Wall -Wextra -pedantic -pthread  PlatformMutex.cpp test_platform_mutex.cpp -o test_platform_mutex

#include <atomic>
#include <iostream>
#include <thread>
#include <vector>

#include "PlatformMutex.h"

namespace {

bool testBasicLocking() {
    tcpmsg::PlatformMutex mutex;
    int counter = 0;

    auto worker = [&]() {
        for (int i = 0; i < 10000; ++i) {
            tcpmsg::PlatformLockGuard lock(mutex);
            ++counter;
        }
    };

    std::thread t1(worker);
    std::thread t2(worker);
    std::thread t3(worker);
    std::thread t4(worker);

    t1.join();
    t2.join();
    t3.join();
    t4.join();

    return counter == 40000;
}

bool testScopedGuard() {
    tcpmsg::PlatformMutex mutex;
    int value = 0;

    {
        tcpmsg::PlatformLockGuard lock(mutex);
        value = 42;
    }

    {
        tcpmsg::PlatformLockGuard lock(mutex);
        value += 1;
    }

    return value == 43;
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

    if (!runTest("basic_locking", testBasicLocking)) ++fails;
    if (!runTest("scoped_guard", testScopedGuard)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all PlatformMutex tests passed\n";
    return 0;
}