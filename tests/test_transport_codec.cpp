// c++ -std=c++17 -Wall -Wextra -pedantic FrameAccumulator.cpp TransportCodec.cpp test_transport_codec.cpp -o test_transport_codec
#include <cstdint>
#include <iostream>
#include <vector>

#include "TransportCodec.h"
#include "FrameAccumulator.h"
#include "Config.h"

using tcpmsg::TransportCodec;
using tcpmsg::FrameAccumulator;
using tcpmsg::MACAddress;

namespace {

bool feedFrame(FrameAccumulator& acc, const std::vector<uint8_t>& frame) {
    bool completed = false;
    for (size_t i = 0; i < frame.size(); ++i) {
        const bool now = acc.feed(frame[i]);
        if (now) {
            if (i + 1 != frame.size()) return false;
            completed = true;
        }
    }
    return completed;
}

MACAddress makeMac(uint8_t a0, uint8_t a1, uint8_t a2,
                   uint8_t a3, uint8_t a4, uint8_t a5) {
    const uint8_t raw[6] = {a0, a1, a2, a3, a4, a5};
    return MACAddress(raw);
}

bool sameMac(const MACAddress& a, const MACAddress& b) {
    return a == b;
}

bool testBuildAndParseDataFrame() {
    const MACAddress src = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress dst = makeMac(10, 11, 12, 13, 14, 15);
    const uint16_t seq = 0x1234;
    const uint8_t payload[] = {0xAA, 0xBB, 0xCC};

    std::vector<uint8_t> frame;
    if (!TransportCodec::buildDataFrame(frame, src, dst, seq, payload, sizeof(payload))) {
        return false;
    }

    FrameAccumulator acc;
    if (!feedFrame(acc, frame)) return false;
    if (!acc.complete()) return false;
    if (acc.frameKind() != FrameAccumulator::FrameKind::Data) return false;

    TransportCodec::ParsedDataPayload parsed;
    if (!TransportCodec::parseDataPayload(acc.payload(), acc.payloadLen(), parsed)) {
        return false;
    }

    if (!sameMac(parsed.srcMac, src)) return false;
    if (!sameMac(parsed.dstMac, dst)) return false;
    if (parsed.seq != seq) return false;
    if (parsed.payloadLen != sizeof(payload)) return false;
    if (!parsed.payload) return false;

    for (size_t i = 0; i < sizeof(payload); ++i) {
        if (parsed.payload[i] != payload[i]) return false;
    }

    return true;
}

bool testBuildAndParseAckFrame() {
    const uint16_t seq = 0xBEEF;
    const uint8_t flags = 0x5A;

    std::vector<uint8_t> frame;
    if (!TransportCodec::buildAckFrame(frame, seq, TransportCodec::AckCode::QueueFull, flags)) {
        return false;
    }

    FrameAccumulator acc;
    if (!feedFrame(acc, frame)) return false;
    if (!acc.complete()) return false;
    if (acc.frameKind() != FrameAccumulator::FrameKind::Ack) return false;

    TransportCodec::ParsedAckPayload parsed;
    if (!TransportCodec::parseAckPayload(acc.payload(), acc.payloadLen(), parsed)) {
        return false;
    }

    return parsed.seq == seq &&
           parsed.code == TransportCodec::AckCode::QueueFull &&
           parsed.flags == flags;
}

bool testZeroLengthDataPayload() {
    const MACAddress src = makeMac(1, 1, 1, 1, 1, 1);
    const MACAddress dst = makeMac(2, 2, 2, 2, 2, 2);
    const uint16_t seq = 7;

    std::vector<uint8_t> frame;
    if (!TransportCodec::buildDataFrame(frame, src, dst, seq, nullptr, 0)) {
        return false;
    }

    FrameAccumulator acc;
    if (!feedFrame(acc, frame)) return false;

    TransportCodec::ParsedDataPayload parsed;
    if (!TransportCodec::parseDataPayload(acc.payload(), acc.payloadLen(), parsed)) {
        return false;
    }

    return parsed.seq == seq &&
           sameMac(parsed.srcMac, src) &&
           sameMac(parsed.dstMac, dst) &&
           parsed.payloadLen == 0 &&
           parsed.payload == nullptr;
}

bool testTooLargeDataRejected() {
    const MACAddress src = makeMac(1, 2, 3, 4, 5, 6);
    const MACAddress dst = makeMac(7, 8, 9, 10, 11, 12);

    const uint16_t payloadLen =
        static_cast<uint16_t>(tcpmsg::kFrameMaxPayloadLen - TransportCodec::kDataHeaderSize + 1);

    std::vector<uint8_t> payload(payloadLen, 0x42);
    std::vector<uint8_t> frame;

    return !TransportCodec::buildDataFrame(frame, src, dst, 1, payload.data(), payloadLen);
}

bool testParseAckRejectsInvalidCode() {
    const uint8_t raw[TransportCodec::kAckPayloadSize] = {
        0x34, 0x12, 0xFF, 0x00
    };

    TransportCodec::ParsedAckPayload parsed;
    return !TransportCodec::parseAckPayload(raw, sizeof(raw), parsed);
}

bool testParseDataRejectsTooShortPayload() {
    const uint8_t raw[TransportCodec::kDataHeaderSize - 1] = {0};

    TransportCodec::ParsedDataPayload parsed;
    return !TransportCodec::parseDataPayload(raw, sizeof(raw), parsed);
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

    if (!runTest("build_parse_data_frame", testBuildAndParseDataFrame)) ++fails;
    if (!runTest("build_parse_ack_frame", testBuildAndParseAckFrame)) ++fails;
    if (!runTest("zero_length_data_payload", testZeroLengthDataPayload)) ++fails;
    if (!runTest("too_large_data_rejected", testTooLargeDataRejected)) ++fails;
    if (!runTest("parse_ack_rejects_invalid_code", testParseAckRejectsInvalidCode)) ++fails;
    if (!runTest("parse_data_rejects_too_short", testParseDataRejectsTooShortPayload)) ++fails;

    if (fails != 0) {
        std::cout << "[FAIL] total failed: " << fails << "\n";
        return 1;
    }

    std::cout << "[ OK ] all TransportCodec tests passed\n";
    return 0;
}