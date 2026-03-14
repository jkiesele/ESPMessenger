#include "PlatformMutex.h"

#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))

#include <mutex>
#include <new>
#include <cstdio>
#include <cstdlib>

namespace tcpmsg {

struct PlatformMutex::State {
    std::mutex mutex;
};

PlatformMutex::PlatformMutex() {
    state_ = new (std::nothrow) State();

    if (!state_) {
        std::fprintf(stderr, "tcpmsg: PlatformMutex construction failed\n");
    }
}

PlatformMutex::~PlatformMutex() {
    delete state_;
    state_ = nullptr;
}

void PlatformMutex::lock() {
    if (!state_) {
        std::fprintf(stderr, "tcpmsg: PlatformMutex::lock on invalid mutex\n");
        std::abort();
    }
    state_->mutex.lock();
}

void PlatformMutex::unlock() {
    if (!state_) {
        std::fprintf(stderr, "tcpmsg: PlatformMutex::unlock on invalid mutex\n");
        std::abort();
    }
    state_->mutex.unlock();
}

} // namespace tcpmsg

#else

#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <cstdlib>

namespace tcpmsg {

struct PlatformMutex::State {
    SemaphoreHandle_t handle = nullptr;
};

PlatformMutex::PlatformMutex() {
    state_ = new State();
    if (state_) {
        state_->handle = xSemaphoreCreateMutex();
        if (!state_->handle) {
            delete state_;
            state_ = nullptr;
            abort();
        }
    }
    else{
        abort();
    }
}

PlatformMutex::~PlatformMutex() {
    if (state_) {
        if (state_->handle) {
            vSemaphoreDelete(state_->handle);
            state_->handle = nullptr;
        }
        delete state_;
        state_ = nullptr;
    }
}

void PlatformMutex::lock() {
    if (!state_ || !state_->handle) {
        abort();
    }
    xSemaphoreTake(state_->handle, portMAX_DELAY);
}

void PlatformMutex::unlock() {
    if (!state_ || !state_->handle) {
        abort();
    }
    xSemaphoreGive(state_->handle);
}

} // namespace tcpmsg

#endif