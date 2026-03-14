#pragma once

#include <cstdint>
#include <vector>

namespace tcpmsg {

class MessengerCodec {
public:
    struct ParsedMessage {
        uint8_t type = 0;
        uint8_t chanId = 0;
        const uint8_t* encryptedPayload = nullptr;
        uint16_t encryptedPayloadLen = 0;
    };

    static constexpr uint16_t kHeaderSize = 4;

    static bool buildMessage(std::vector<uint8_t>& out,
                             uint8_t type,
                             uint8_t chanId,
                             const uint8_t* encryptedPayload,
                             uint16_t encryptedPayloadLen);

    static bool parseMessage(const uint8_t* data,
                             uint16_t len,
                             ParsedMessage& out);
};

} // namespace tcpmsg