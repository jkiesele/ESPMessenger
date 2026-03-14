#pragma once

namespace tcpmsg {

class PlatformMutex {
public:
    PlatformMutex();
    ~PlatformMutex();

    PlatformMutex(const PlatformMutex&) = delete;
    PlatformMutex& operator=(const PlatformMutex&) = delete;

    void lock();
    void unlock();

    bool isValid() const { return state_ != nullptr; }

private:
    struct State;
    State* state_ = nullptr;
};

class PlatformLockGuard {
public:
    explicit PlatformLockGuard(PlatformMutex& mutex)
        : mutex_(mutex) {
        mutex_.lock();
    }

    ~PlatformLockGuard() {
        mutex_.unlock();
    }

    PlatformLockGuard(const PlatformLockGuard&) = delete;
    PlatformLockGuard& operator=(const PlatformLockGuard&) = delete;

private:
    PlatformMutex& mutex_;
};

} // namespace tcpmsg