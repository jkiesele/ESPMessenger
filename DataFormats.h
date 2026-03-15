#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "PacketIO.h"
#include "Serializable.h"

namespace tcpmsg {
namespace formats {



/**
 * @brief Shared reservoir state payload.
 *
 * Wire layout:
 * - level        : float32
 * - emptyLevel   : float32
 * - capacity     : float32
 * - temperature  : float32
 */
class ReservoirInfo : public Serializable {
public:
    ReservoirInfo()
        : level_(0.0f), emptyLevel_(0.0f), capacity_(0.0f), temperature_(0.0f) {}

    static constexpr uint8_t TYPE_ID = 0x01;
    uint8_t typeId() const override { return TYPE_ID; }

    uint16_t payloadSize() const override { return 16; }

    void serializeTo(uint8_t* dst) const override {
        PacketWriter w(dst, payloadSize());
        w.write(level_);
        w.write(emptyLevel_);
        w.write(capacity_);
        w.write(temperature_);
        // w.write(name_);
    }

    bool fromBuffer(const uint8_t* src, uint16_t len) override {
        if (len < payloadSize()) return false;

        PacketReader r(src, len);
        return r.read(level_) &&
               r.read(emptyLevel_) &&
               r.read(capacity_) &&
               r.read(temperature_) &&
               // r.read(name_) &&
               r.atEnd();
    }

    // in percent, e.g. 75.5 for 75.5%
    float level() const { return level_; }
    // in percent, e.g. 75.5 for 75.5%
    void setLevel(float v) { level_ = v; }

    // in percent, e.g. 75.5 for 75.5%
    float emptyLevel() const { return emptyLevel_; }
    // in percent, e.g. 75.5 for 75.5%
    void setEmptyLevel(float v) { emptyLevel_ = v; }

    // in liters 
    float capacity() const { return capacity_; }
    // in liters 
    void setCapacity(float v) { capacity_ = v; }

    float temperature() const { return temperature_; }
    void setTemperature(float v) { temperature_ = v; }

    const ByteString& name() const { return name_; }
    void setName(const char* s) { name_.assign(s); }

    float litersFullMin() const {
        return capacity_ * (level_ / 100.0f);
    }

    float litersEmptyMin() const {
        return capacity_ * (emptyLevel_ / 100.0f);
    }

protected:
    float level_;
    float emptyLevel_;
    float capacity_;
    float temperature_;
    ByteString name_; //not transmitted
};

class TextMessage : public Serializable {
public:
    static constexpr uint8_t TYPE_ID = 0x02;

    TextMessage() = default;
    explicit TextMessage(const char* s) : text_(s) {}

    uint8_t typeId() const override { return TYPE_ID; }

    uint16_t payloadSize() const override {
        return static_cast<uint16_t>(2 + text_.size());
    }

    void serializeTo(uint8_t* dst) const override {
        PacketWriter w(dst, payloadSize());
        w.write(text_);
    }

    bool fromBuffer(const uint8_t* src, uint16_t len) override {
        PacketReader r(src, len);
        return r.read(text_) && r.atEnd();
    }

    const ByteString& text() const { return text_; }
    ByteString& text() { return text_; }

    void setText(const char* s) { text_.assign(s); }
    void setText(const uint8_t* src, uint16_t len) { text_.assign(src, len); }

private:
    ByteString text_;
};


} // namespace formats
} // namespace tcpmsg