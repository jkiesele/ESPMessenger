#pragma once

#include <cstdint>

namespace tcpmsg {

class PlatformThread {
public:
    using Entry = void (*)(void*);

    PlatformThread() = default;
    ~PlatformThread();

    PlatformThread(const PlatformThread&) = delete;
    PlatformThread& operator=(const PlatformThread&) = delete;

    bool start(Entry entry,
               void* context,
               const char* name,
               uint32_t stackSize = 4096);

    bool isRunning() const;
    bool waitUntilStopped(uint32_t timeoutMs);

    static void sleepMs(uint32_t ms);

    struct State;
private:
    State* state_ = nullptr;
};

} // namespace tcpmsg