#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace tcpmsg {

class ByteString {
public:
    ByteString() = default;

    // Convenience for C-style text input.
    // The input is treated as a zero-terminated string and copied without the trailing '\0'.
    // For binary data or embedded '\0' bytes, use assign(const uint8_t*, uint16_t).
    explicit ByteString(const char* s) { assign(s); }

    ByteString(const uint8_t* src, uint16_t len) { assign(src, len); }

    void clear() { bytes_.clear(); }

    uint16_t size() const { return static_cast<uint16_t>(bytes_.size()); }
    bool empty() const { return bytes_.empty(); }

    const uint8_t* data() const { return bytes_.empty() ? nullptr : bytes_.data(); }
    uint8_t* data() { return bytes_.empty() ? nullptr : bytes_.data(); }

    void assign(const char* s) {
        if (!s) {
            bytes_.clear();
            return;
        }
        const size_t n = std::strlen(s);
        bytes_.assign(reinterpret_cast<const uint8_t*>(s),
                      reinterpret_cast<const uint8_t*>(s) + n);
    }

    void assign(const uint8_t* src, uint16_t len) {
        if (!src || len == 0) {
            bytes_.clear();
            return;
        }
        bytes_.assign(src, src + len);
    }

    bool operator==(const ByteString& o) const { return bytes_ == o.bytes_; }
    bool operator!=(const ByteString& o) const { return !(*this == o); }

private:
    friend class PacketWriter;
    friend class PacketReader;
    std::vector<uint8_t> bytes_;
};

/**
 * @brief Small cursor-based helpers for binary serialization.
 *
 * Scope:
 * - primitive fixed-size values
 * - raw byte blocks
 * - length-prefixed byte blocks
 *
 * Non-goals:
 * - no string handling
 * - no STL/container magic
 * - no transport or messenger semantics
 * - no platform-specific types
 *
 * Conventions:
 * - multibyte integers are encoded little-endian
 * - float is serialized as raw IEEE754 float32 bytes
 * - writer/reader become permanently invalid after the first bounds/error failure
 */

class PacketWriter {
public:
    PacketWriter(uint8_t* buffer, uint16_t capacity)
        : buffer_(buffer), capacity_(capacity) {}

    uint16_t size() const { return pos_; }
    uint16_t capacity() const { return capacity_; }
    uint16_t remaining() const { return static_cast<uint16_t>(capacity_ - pos_); }
    bool ok() const { return ok_; }

    uint8_t* data() { return buffer_; }
    const uint8_t* data() const { return buffer_; }

    void reset() {
        pos_ = 0;
        ok_ = true;
    }

    bool write(uint8_t v) {
        return writeBytes(&v, 1);
    }

    bool write(uint16_t v) {
        uint8_t tmp[2];
        tmp[0] = static_cast<uint8_t>(v & 0xFF);
        tmp[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        return writeBytes(tmp, 2);
    }

    bool write(uint32_t v) {
        uint8_t tmp[4];
        tmp[0] = static_cast<uint8_t>(v & 0xFF);
        tmp[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        tmp[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        tmp[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        return writeBytes(tmp, 4);
    }

    bool write(int32_t v) {
        return write(static_cast<uint32_t>(v));
    }

    bool write(float v) {
        static_assert(sizeof(float) == 4, "PacketIO assumes 32-bit float");
        uint32_t raw = 0;
        std::memcpy(&raw, &v, sizeof(raw));
        return write(raw);
    }

    bool write(bool v) {
        const uint8_t b = v ? 1u : 0u;
        return write(b);
    }

    bool write(const ByteString& s) {
        return writeLen16Bytes(s.data(), s.size());
    }

    bool writeBytes(const void* src, uint16_t len) {
        if (!ok_ || buffer_ == nullptr || (len > 0 && src == nullptr)) {
            ok_ = false;
            return false;
        }
        if (len > remaining()) {
            ok_ = false;
            return false;
        }

        if (len > 0) {
            std::memcpy(buffer_ + pos_, src, len);
            pos_ = static_cast<uint16_t>(pos_ + len);
        }
        return true;
    }

    bool writeLen16Bytes(const void* src, uint16_t len) {
        return write(len) && writeBytes(src, len);
    }

private:
    uint8_t* buffer_ = nullptr;
    uint16_t capacity_ = 0;
    uint16_t pos_ = 0;
    bool ok_ = true;
};

class PacketReader {
public:
    PacketReader(const uint8_t* buffer, uint16_t size)
        : buffer_(buffer), size_(size) {}

    uint16_t size() const { return size_; }
    uint16_t position() const { return pos_; }
    uint16_t remaining() const { return static_cast<uint16_t>(size_ - pos_); }
    bool ok() const { return ok_; }
    bool atEnd() const { return ok_ && pos_ == size_; }

    const uint8_t* data() const { return buffer_; }

    void reset() {
        pos_ = 0;
        ok_ = true;
    }

    bool read(uint8_t& out) {
        return readBytes(&out, 1);
    }

    bool read(uint16_t& out) {
        uint8_t tmp[2];
        if (!readBytes(tmp, 2)) {
            return false;
        }
        out = static_cast<uint16_t>(tmp[0]) |
              (static_cast<uint16_t>(tmp[1]) << 8);
        return true;
    }

    bool read(uint32_t& out) {
        uint8_t tmp[4];
        if (!readBytes(tmp, 4)) {
            return false;
        }
        out = static_cast<uint32_t>(tmp[0]) |
              (static_cast<uint32_t>(tmp[1]) << 8) |
              (static_cast<uint32_t>(tmp[2]) << 16) |
              (static_cast<uint32_t>(tmp[3]) << 24);
        return true;
    }

    bool read(int32_t& out) {
        uint32_t raw = 0;
        if (!read(raw)) {
            return false;
        }
        out = static_cast<int32_t>(raw);
        return true;
    }

    bool read(float& out) {
        static_assert(sizeof(float) == 4, "PacketIO assumes 32-bit float");
        uint32_t raw = 0;
        if (!read(raw)) {
            return false;
        }
        std::memcpy(&out, &raw, sizeof(out));
        return true;
    }

    bool read(bool& out) {
        uint8_t b = 0;
        if (!read(b)) {
            return false;
        }
        if (b > 1u) {
            ok_ = false;
            return false;
        }
        out = (b != 0u);
        return true;
    }

    bool read(ByteString& s) {
        const uint8_t* ptr = nullptr;
        uint16_t len = 0;
        if (!readLen16Bytes(ptr, len)) {
            return false;
        }
        s.assign(ptr, len);
        return true;
    }

    bool readBytes(void* dst, uint16_t len) {
        if (!ok_ || buffer_ == nullptr || (len > 0 && dst == nullptr)) {
            ok_ = false;
            return false;
        }
        if (len > remaining()) {
            ok_ = false;
            return false;
        }

        if (len > 0) {
            std::memcpy(dst, buffer_ + pos_, len);
            pos_ = static_cast<uint16_t>(pos_ + len);
        }
        return true;
    }

    /**
     * @brief Read one uint16 length prefix and return a zero-copy view onto the bytes.
     *
     * outPtr points into the original reader buffer.
     */
    bool readLen16Bytes(const uint8_t*& outPtr, uint16_t& outLen) {
        uint16_t len = 0;
        if (!read(len)) {
            return false;
        }
        if (len > remaining()) {
            ok_ = false;
            return false;
        }

        outPtr = buffer_ + pos_;
        outLen = len;
        pos_ = static_cast<uint16_t>(pos_ + len);
        return true;
    }

    bool skip(uint16_t len) {
        if (!ok_) {
            return false;
        }
        if (len > remaining()) {
            ok_ = false;
            return false;
        }
        pos_ = static_cast<uint16_t>(pos_ + len);
        return true;
    }

private:
    const uint8_t* buffer_ = nullptr;
    uint16_t size_ = 0;
    uint16_t pos_ = 0;
    bool ok_ = true;
};

} // namespace tcpmsg