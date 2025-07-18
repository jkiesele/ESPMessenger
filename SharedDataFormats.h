#ifndef SHARED_DATA_FORMATS_H
#define SHARED_DATA_FORMATS_H

#include <PacketIO.h>
#include <Serializable.h>

namespace SharedDataFormats {

// ------------------------------------------------------------------
// 0x01  ReservoirInfo  – three float32 values
// ------------------------------------------------------------------
class ReservoirInfo : public Serializable {
public:
    ReservoirInfo() : level_(0), capacity_(0), temperature_(0) {}

    // --- Serializable interface ------------------------------------
    static constexpr uint8_t TYPE_ID = 0x01;
    uint8_t  typeId()      const override { return TYPE_ID; }

    void serializeTo(uint8_t* dst) const override {
        PacketWriter w(dst, payloadSize());
        w.write(level_);
        w.write(capacity_);
        w.write(temperature_);
        // w.ok() is guaranteed because we pre-sized the buffer.
    }

    bool fromBuffer(const uint8_t* src, uint16_t len) override {
        if (len < payloadSize()) return false;                  // length guard
        PacketReader r(src, len);
        return r.read(level_)     &&
               r.read(capacity_)  &&
               r.read(temperature_) &&
               r.atEnd();                                      // exact fit
    }

    // --- Accessors --------------------------------------------------
    float level()       const { return level_; }
    void  setLevel(float v) { level_ = v; }

    float capacity()    const { return capacity_; }
    void  setCapacity(float v) { capacity_ = v; }

    float temperature() const { return temperature_; }
    void  setTemperature(float v) { temperature_ = v; }


    uint16_t payloadSize() const override { return 12; }        // 3 × float32

protected: //protected so that we can use it in derived classes
    float level_;        // e.g. 0-100 %
    float capacity_;     // litres
    float temperature_;  // °C
};

class SensorAM2302 : public Serializable {
public:
    SensorAM2302() : humidity_(0), temperature_(0) {}
    // --- Serializable interface ------------------------------------
    static constexpr uint8_t TYPE_ID = 0x02;
    uint8_t  typeId()      const override { return TYPE_ID; }
    void serializeTo(uint8_t* dst) const override {
        PacketWriter w(dst, payloadSize());
        w.write(humidity_);
        w.write(temperature_);
        // w.ok() is guaranteed because we pre-sized the buffer.
    }
    bool fromBuffer(const uint8_t* src, uint16_t len) override {
        if (len < payloadSize()) return false;                  // length guard
        PacketReader r(src, len);
        return r.read(humidity_) &&
               r.read(temperature_) &&
               r.atEnd();                                      // exact fit
    }
    // --- Accessors --------------------------------------------------
    float humidity()     const { return humidity_; }
    void  setHumidity(float v) { humidity_ = v; }
    float temperature()  const { return temperature_; }
    void  setTemperature(float v) { temperature_ = v; }
    uint16_t payloadSize() const override { return 8; }        // 2 × float32

private:
    float humidity_;     // e.g. 0-100 %
    float temperature_;  // °C
};


} // namespace SharedDataFormats
#endif // SHARED_DATA_FORMATS_H