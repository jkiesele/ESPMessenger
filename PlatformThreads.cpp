#include "PlatformThreads.h"

#if defined(__linux__) || (defined(__APPLE__) && defined(__MACH__))

#include <thread>
#include <atomic>
#include <chrono>
#include <new>
#include <cstdlib>

namespace tcpmsg {

struct PlatformThread::State {
    std::thread thread;
    std::atomic<bool> running{false};
};

namespace {
struct TrampolineCtx {
    PlatformThread::Entry entry = nullptr;
    void* context = nullptr;
    PlatformThread::State* state = nullptr;
};

void threadMain(TrampolineCtx* ctx) {
    ctx->entry(ctx->context);
    ctx->state->running.store(false);
    delete ctx;
}
}

PlatformThread::~PlatformThread() {
    if (state_ && state_->running.load()) {
        std::fprintf(stderr, "tcpmsg: destroying PlatformThread while still running\n");
        std::abort();
    }
    releaseFinishedState_();
}

bool PlatformThread::start(Entry entry,
                           void* context,
                           const char*,
                           uint32_t) {
    if (!entry) return false;

    releaseFinishedState_();
    if (state_) return false;

    state_ = new (std::nothrow) State();
    if (!state_) return false;

    state_->running.store(true);

    TrampolineCtx* ctx = new (std::nothrow) TrampolineCtx();
    if (!ctx) {
        delete state_;
        state_ = nullptr;
        return false;
    }

    ctx->entry = entry;
    ctx->context = context;
    ctx->state = state_;

    try {
        state_->thread = std::thread(threadMain, ctx);
    } catch (...) {
        state_->running.store(false);
        delete ctx;
        delete state_;
        state_ = nullptr;
        return false;
    }

    return true;
}

bool PlatformThread::isRunning() const {
    return state_ && state_->running.load();
}

bool PlatformThread::waitUntilStopped(uint32_t timeoutMs) {
    if (!state_) return true;

    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);

    while (state_->running.load()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            return false;
        }
        sleepMs(10);
    }
    return true;
}

void PlatformThread::sleepMs(uint32_t ms) {
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

void PlatformThread::releaseFinishedState_() {
    if (!state_) {
        return;
    }
    if (state_->running.load()) {
        return;
    }
    if (state_->thread.joinable()) {
        state_->thread.join();
    }
    delete state_;
    state_ = nullptr;
}

} // namespace tcpmsg

#else

#include <atomic>
#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <cstdlib>

namespace tcpmsg {

struct PlatformThread::State {
    TaskHandle_t handle = nullptr;
    std::atomic<bool> running{false};
    Entry entry = nullptr;
    void* context = nullptr;
};

namespace {
void taskMain(void* arg) {
    auto* state = static_cast<PlatformThread::State*>(arg);
    state->entry(state->context);
    state->running.store(false);
    vTaskDelete(nullptr);
}
}

PlatformThread::~PlatformThread() {
    if (state_ && state_->running.load()) {
        abort();
    }
    releaseFinishedState_();
}

bool PlatformThread::start(Entry entry,
                           void* context,
                           const char* name,
                           uint32_t stackSize) {

    if (!entry) return false;

    releaseFinishedState_();
    if (state_) return false;

    state_ = new State();
    if (!state_) return false;

    state_->entry = entry;
    state_->context = context;
    state_->running.store(true);

    BaseType_t rc = xTaskCreate(
        taskMain,
        name ? name : "tcpmsg",
        stackSize,
        state_,
        1,
        &state_->handle
    );

    if (rc != pdPASS) {
        state_->running.store(false);
        delete state_;
        state_ = nullptr;
        return false;
    }

    return true;
}

bool PlatformThread::isRunning() const {
    return state_ && state_->running.load();
}

bool PlatformThread::waitUntilStopped(uint32_t timeoutMs) {
    if (!state_) return true;

    const uint32_t start = millis();
    while (state_->running.load()) {
        if ((millis() - start) >= timeoutMs) {
            return false;
        }
        sleepMs(10);
    }
    return true;
}

void PlatformThread::sleepMs(uint32_t ms) {
    vTaskDelay(pdMS_TO_TICKS(ms));
}

void PlatformThread::releaseFinishedState_() {
    if (!state_) {
        return;
    }
    if (state_->running.load()) {
        return;
    }
    delete state_;
    state_ = nullptr;
}

} // namespace tcpmsg

#endif