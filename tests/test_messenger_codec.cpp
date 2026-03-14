// c++ -std=c++17 -Wall -Wextra -pedantic MessengerCodec.cpp test_messenger_codec.cpp -o test_messenger_codec

#include <cstdint>
#include <iostream>
#include <vector>

#include "MessengerCodec.h"

using tcpmsg::MessengerCodec;

namespace {

bool testBuildAndParse() {
    const uint8_t encrypted[] = {0x11, 0x22, 0x33, 0x44};

    std::vector<uint8_t> msg;
    if (!MessengerCodec::buildMessage(msg, 7, 9, encrypted, sizeof(encrypted))) {
        return false;
    }

    MessengerCodec::ParsedMessage parsed;
    if (!MessengerCodec::parseMessage(msg.data(),
                                      static_cast<uint16_t>(msg.size()),
                                      parsed)) {
        return false;
    }

    if (parsed.type != 7) return false;
    if (parsed.chanId != 9) return false;
    if (parsed.encryptedPayloadLen != sizeof(encrypted)) return false;
    if (!parsed.encryptedPayload) return false;

    for (size_t i = 0; i < sizeof(encrypted); ++i) {
        if (parsed.encryptedPayload[i] != encrypted[i]) return false;
    }
    return true;
}

bool testZeroLengthPayload() {
    std::vector<uint8_t> msg;
    if (!MessengerCodec::buildMessage(msg, 1, 2, nullptr, 0)) {
        return false;
    }

    MessengerCodec::ParsedMessage parsed;
    if (!MessengerCodec::parseMessage(msg.data(),
                                      static_cast<uint16_t>(msg.size()),
                                      parsed)) {
        return false;
    }

    return parsed.type == 1 &&
           parsed.chanId == 2 &&
           parsed.encryptedPayloadLen == 0 &&
           parsed.encryptedPayload == nullptr;
}

bool testRejectTooShort() {
    const uint8_t raw[] = {1, 2, 3};
    MessengerCodec::ParsedMessage parsed;
    return !MessengerCodec::parseMessage(raw, sizeof(raw), parsed);
}

bool testRejectLengthMismatch() {
    const uint8_t raw[] = {
        1, 2, 4, 0,   // says payload len = 4
        0xAA, 0xBB    // but only 2 bytes follow
    };

    MessengerCodec::ParsedMessage parsed;
    return !MessengerCodec::parseMessage(raw, sizeof(raw), parsed);
}

bool testRejectNullNonZero() {
    std::vector<uint8_t> msg;
    return !MessengerCodec::buildMessage(msg, 1, 2, nullptr, 3);
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

    if (!runTest("build_and_parse", testBuildAndParse)) ++fails;
    if (!runTest("zero_length_payload", testZeroLengthPayload)) ++fails;
    if (!runTest("reject_too_short", testRejectTooShort)) ++fails;
    if (!runTest("reject_length_mismatch", testRejectLengthMismatch)) ++fails;
    if (!runTest("reject_null_nonzero", testRejectNullNonZero)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all MessengerCodec tests passed\n";
    return 0;
}