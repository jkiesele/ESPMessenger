// c++ -std=c++17 -Wall -Wextra -pedantic FrameAccumulator.cpp test_frame_accumulator.cpp -o test_frame_accumulator

#include <cstdint>
#include <iostream>
#include <vector>

#include "FrameAccumulator.h"

using tcpmsg::FrameAccumulator;

namespace {

bool feedAll(FrameAccumulator& acc, const std::vector<uint8_t>& bytes, bool expectCompleteAtEndOnly = true) {
    bool gotComplete = false;

    for (size_t i = 0; i < bytes.size(); ++i) {
        const bool completeNow = acc.feed(bytes[i]);
        if (completeNow) {
            if (expectCompleteAtEndOnly && i + 1 != bytes.size()) {
                return false;
            }
            gotComplete = true;
        }
    }
    return gotComplete;
}

bool testValidDataFrame() {
    FrameAccumulator acc;

    const std::vector<uint8_t> frame = {
        1, 0, 3, 0,   // kind=Data, reserved=0, len=3
        0x11, 0x22, 0x33
    };

    if (!feedAll(acc, frame)) return false;
    if (!acc.complete()) return false;
    if (acc.invalid()) return false;
    if (acc.frameKind() != FrameAccumulator::FrameKind::Data) return false;
    if (acc.payloadLen() != 3) return false;

    const uint8_t* p = acc.payload();
    if (!p) return false;
    return p[0] == 0x11 && p[1] == 0x22 && p[2] == 0x33;
}

bool testValidAckFrame() {
    FrameAccumulator acc;

    const std::vector<uint8_t> frame = {
        2, 0, 2, 0,   // kind=Ack, reserved=0, len=2
        0xAA, 0x55
    };

    if (!feedAll(acc, frame)) return false;
    if (!acc.complete()) return false;
    if (acc.frameKind() != FrameAccumulator::FrameKind::Ack) return false;
    if (acc.payloadLen() != 2) return false;

    const uint8_t* p = acc.payload();
    if (!p) return false;
    return p[0] == 0xAA && p[1] == 0x55;
}

bool testZeroLengthPayload() {
    FrameAccumulator acc;

    const std::vector<uint8_t> frame = {
        1, 0, 0, 0    // kind=Data, reserved=0, len=0
    };

    if (!feedAll(acc, frame)) return false;
    if (!acc.complete()) return false;
    if (acc.frameKind() != FrameAccumulator::FrameKind::Data) return false;
    if (acc.payloadLen() != 0) return false;
    if (acc.payload() != nullptr) return false;
    return true;
}

bool testInvalidFrameKind() {
    FrameAccumulator acc;

    const std::vector<uint8_t> frame = {
        9, 0, 1, 0,   // invalid kind
        0x42
    };

    if (feedAll(acc, frame, false)) return false;
    if (!acc.invalid()) return false;
    if (acc.complete()) return false;
    return true;
}

bool testPayloadTooLarge() {
    FrameAccumulator acc;

    const uint16_t tooLarge = tcpmsg::kFrameMaxPayloadLen + 1;
    const std::vector<uint8_t> frame = {
        1,
        0,
        static_cast<uint8_t>(tooLarge & 0xFF),
        static_cast<uint8_t>((tooLarge >> 8) & 0xFF)
    };

    if (feedAll(acc, frame, false)) return false;
    if (!acc.invalid()) return false;
    if (acc.complete()) return false;
    return true;
}

bool testNoAutoResetAfterComplete() {
    FrameAccumulator acc;

    const std::vector<uint8_t> frame = {
        1, 0, 1, 0,
        0x77
    };

    if (!feedAll(acc, frame)) return false;
    if (!acc.complete()) return false;

    // Extra byte must not start a new frame implicitly.
    if (acc.feed(1)) return false;
    if (!acc.complete()) return false;
    if (acc.invalid()) return false;

    return acc.payloadLen() == 1 && acc.payload() && acc.payload()[0] == 0x77;
}

bool testExplicitReset() {
    FrameAccumulator acc;

    const std::vector<uint8_t> frame1 = {
        1, 0, 1, 0,
        0x33
    };

    if (!feedAll(acc, frame1)) return false;
    if (!acc.complete()) return false;

    acc.reset();

    if (acc.complete()) return false;
    if (acc.invalid()) return false;
    if (acc.payloadLen() != 0) return false;
    if (acc.payload() != nullptr) return false;

    const std::vector<uint8_t> frame2 = {
        2, 0, 2, 0,
        0x10, 0x20
    };

    if (!feedAll(acc, frame2)) return false;
    if (!acc.complete()) return false;
    if (acc.frameKind() != FrameAccumulator::FrameKind::Ack) return false;
    if (acc.payloadLen() != 2) return false;

    const uint8_t* p = acc.payload();
    if (!p) return false;
    return p[0] == 0x10 && p[1] == 0x20;
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

    if (!runTest("valid_data_frame", testValidDataFrame)) ++fails;
    if (!runTest("valid_ack_frame", testValidAckFrame)) ++fails;
    if (!runTest("zero_length_payload", testZeroLengthPayload)) ++fails;
    if (!runTest("invalid_frame_kind", testInvalidFrameKind)) ++fails;
    if (!runTest("payload_too_large", testPayloadTooLarge)) ++fails;
    if (!runTest("no_auto_reset_after_complete", testNoAutoResetAfterComplete)) ++fails;
    if (!runTest("explicit_reset", testExplicitReset)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all FrameAccumulator tests passed\n";
    return 0;
}