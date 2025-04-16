#ifndef ESP_MESSENGER_DATAFORMATS_H
#define ESP_MESSENGER_DATAFORMATS_H

#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

namespace DataFormats {


// For transparent interface also add one for uint8_t
inline void serialize(std::vector<uint8_t>& packet, uint8_t value) {
    packet.push_back(value);
}
inline void deserialize(std::vector<uint8_t>& packet, uint8_t& value) {
    if (packet.empty()) {
        throw std::runtime_error("Not enough data to deserialize uint8_t");
    }
    value = packet[0];
    packet.erase(packet.begin());
}


// Serialize a 32-bit unsigned integer into the packet (little-endian).
inline void serialize(std::vector<uint8_t>& packet, uint32_t value) {
    packet.push_back(static_cast<uint8_t>((value >> 0)  & 0xFF));
    packet.push_back(static_cast<uint8_t>((value >> 8)  & 0xFF));
    packet.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    packet.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

// Deserialize a 32-bit unsigned integer from the beginning of packet.
// This function removes the four bytes it reads.
inline void deserialize(std::vector<uint8_t>& packet, uint32_t& value) {
    if (packet.size() < 4) {
        throw std::runtime_error("Not enough data to deserialize uint32_t");
    }
    value = (static_cast<uint32_t>(packet[0]) << 0)  |
            (static_cast<uint32_t>(packet[1]) << 8)  |
            (static_cast<uint32_t>(packet[2]) << 16) |
            (static_cast<uint32_t>(packet[3]) << 24);
    packet.erase(packet.begin(), packet.begin() + 4);
}


// Serialize a 32-bit signed integer by reusing the uint32_t serialization.
inline void serialize(std::vector<uint8_t>& packet, int32_t value) {
    serialize(packet, static_cast<uint32_t>(value));
}

// Deserialize a 32-bit signed integer.
inline void deserialize(std::vector<uint8_t>& packet, int32_t& value) {
    uint32_t tmp;
    deserialize(packet, tmp);
    value = static_cast<int32_t>(tmp);
}

// Serialize a 32-bit float by copying its byte representation.
inline void serialize(std::vector<uint8_t>& packet, float value) {
    uint32_t tmp;
    std::memcpy(&tmp, &value, sizeof(float));
    serialize(packet, tmp);
}

// Deserialize a 32-bit float.
inline void deserialize(std::vector<uint8_t>& packet, float& value) {
    uint32_t tmp;
    deserialize(packet, tmp);
    std::memcpy(&value, &tmp, sizeof(float));
}

// Serialize a vector of type T.
// First writes the size (as a uint32_t), then serializes each element in order.
template <typename T>
void serialize(std::vector<uint8_t>& packet, const std::vector<T>& vec) {
    // First, serialize the number of elements
    uint32_t size = static_cast<uint32_t>(vec.size());
    serialize(packet, size);
    // Then serialize each element
    for (const T& element : vec) {
        serialize(packet, element);
    }
}

// Deserialize a vector of type T.
// First reads the size (as a uint32_t) then deserializes that many elements.
template <typename T>
void deserialize(std::vector<uint8_t>& packet, std::vector<T>& vec) {
    uint32_t size;
    deserialize(packet, size);
    vec.clear();
    for (uint32_t i = 0; i < size; i++) {
        T element;
        deserialize(packet, element);
        vec.push_back(element);
    }
}

// Serialize a string.
inline void serialize(std::vector<uint8_t>& packet, const std::string& str) {
    uint32_t size = static_cast<uint32_t>(str.size());
    serialize(packet, size);
    packet.insert(packet.end(), str.begin(), str.end());
}
// Deserialize a string.
inline void deserialize(std::vector<uint8_t>& packet, std::string& str) {
    uint32_t size;
    deserialize(packet, size);
    if (packet.size() < size) {//sanity check
        throw std::runtime_error("Not enough data to deserialize string");
    }
    str.assign(reinterpret_cast<const char*>(packet.data()), size);
    packet.erase(packet.begin(), packet.begin() + size);
}

// ---- now the actual data formats ----

// ---------------- LogString
class LogString {
public:
    std::string message;
    uint32_t timestamp;
};
// serialize and deserialize
inline void serialize(std::vector<uint8_t>& packet, const LogString& log) {
    serialize(packet, log.message);
    serialize(packet, log.timestamp);
}
inline void deserialize(std::vector<uint8_t>& packet, LogString& log) {
    deserialize(packet, log.message);
    deserialize(packet, log.timestamp);
}
// ---------------- end LogString

// ---------------- ReservoirInfo
class ReservoirInfo {
public:
    
     enum class State : uint8_t {
        EMPTY = 0x00,
        FULL = 0x01,
        MEDIUM = 0x02,
    };
    ReservoirInfo() : state(State::EMPTY), temperature(0.0f), humidity(0.0f) {}

    State state;
    float temperature;
    float humidity;

    //#ifdef DEBUG //for now
    //define stringification (arduino Stringify)
    operator String() const {
        String result = "ReservoirInfo: ";
        result += "State: " + String(static_cast<uint8_t>(state)) + ", ";
        result += "Temperature: " + String(temperature) + ", ";
        result += "Humidity: " + String(humidity);
        return result;
    }
   // #endif
};
// serialize and deserialize
inline void serialize(std::vector<uint8_t>& packet, const ReservoirInfo& info) {
    serialize(packet, static_cast<uint8_t>(info.state));
    serialize(packet, info.temperature);
    serialize(packet, info.humidity);
}
inline void deserialize(std::vector<uint8_t>& packet, ReservoirInfo& info) {
    uint8_t state;
    deserialize(packet, state);
    info.state = static_cast<ReservoirInfo::State>(state);
    deserialize(packet, info.temperature);
    deserialize(packet, info.humidity);
}
// ---------------- end ReservoirInfo


// all data types that can be sent or received
enum class DataType : uint8_t {
    UNKNOWN = 0x00,
    LOG_STRING = 0x01,
    RESERVOIR_INFO = 0x02,
};



} // namespace DataFormats

#endif // ESP_MESSENGER_DATAFORMATS_H