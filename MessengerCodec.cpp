#include "MessengerCodec.h"

#include "Config.h"

namespace tcpmsg {

bool MessengerCodec::buildMessage(std::vector<uint8_t>& out,
                                  uint8_t type,
                                  uint8_t chanId,
                                  const uint8_t* encryptedPayload,
                                  uint16_t encryptedPayloadLen) {
    if (encryptedPayloadLen > 0 && encryptedPayload == nullptr) {
        return false;
    }

    const uint32_t totalLen = static_cast<uint32_t>(kHeaderSize) + encryptedPayloadLen;
    if (totalLen > kFrameMaxPayloadLen) {
        return false;
    }

    out.resize(totalLen);

    out[0] = type;
    out[1] = chanId;
    out[2] = static_cast<uint8_t>(encryptedPayloadLen & 0xFF);
    out[3] = static_cast<uint8_t>((encryptedPayloadLen >> 8) & 0xFF);

    for (uint16_t i = 0; i < encryptedPayloadLen; ++i) {
        out[kHeaderSize + i] = encryptedPayload[i];
    }

    return true;
}

bool MessengerCodec::parseMessage(const uint8_t* data,
                                  uint16_t len,
                                  ParsedMessage& out) {
    if (data == nullptr) {
        return false;
    }

    if (len < kHeaderSize) {
        return false;
    }

    out.type = data[0];
    out.chanId = data[1];

    const uint16_t payloadLen =
        static_cast<uint16_t>(data[2]) |
        (static_cast<uint16_t>(data[3]) << 8);

    if (len != static_cast<uint16_t>(kHeaderSize + payloadLen)) {
        return false;
    }

    out.encryptedPayloadLen = payloadLen;
    out.encryptedPayload = (payloadLen > 0) ? (data + kHeaderSize) : nullptr;

    return true;
}

} // namespace tcpmsg