#ifndef PACKET_IO_H
#define PACKET_IO_H

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>   // memcpy

// ------------------------------------------------------------------
// PacketWriter: cursor-based encoder into caller buffer.
// ------------------------------------------------------------------
class PacketWriter {
public:
    PacketWriter(uint8_t* buf, size_t cap)
    : buf_(buf), cap_(cap), pos_(0), overflow_(false) {}

    void reset(uint8_t* buf, size_t cap) {
        buf_ = buf;
        cap_ = cap;
        pos_ = 0;
        overflow_ = false;
    }

    size_t size() const       { return pos_; }
    size_t capacity() const   { return cap_; }
    size_t remaining() const  { return (pos_ >= cap_) ? 0 : cap_ - pos_; }
    bool   ok() const         { return !overflow_; }

    // ------------------------------------------------------------------
    // Core raw writer
    // ------------------------------------------------------------------
    bool writeBytes(const void* src, size_t n) {
        if (pos_ + n > cap_) { overflow_ = true; pos_ += n; return false; }
        memcpy(buf_ + pos_, src, n);
        pos_ += n;
        return true;
    }

    // ------------------------------------------------------------------
    // Primitive overloads
    // ------------------------------------------------------------------
    bool write(uint8_t v)             { return writeBytes(&v, 1); }
    bool write(int8_t v)              { uint8_t u = static_cast<uint8_t>(v); return write(u); }
    bool write(bool v)                { return write(static_cast<uint8_t>(v ? 1 : 0)); }

    bool write(uint16_t v) { 
        uint8_t tmp[2] = {
            static_cast<uint8_t>( v       & 0xFF),
            static_cast<uint8_t>((v >> 8) & 0xFF)
        };
        return writeBytes(tmp, 2);
    }
    bool write(int16_t v)             { return write(static_cast<uint16_t>(v)); }

    bool write(uint32_t v) {
        uint8_t tmp[4] = {
            static_cast<uint8_t>( v        & 0xFF),
            static_cast<uint8_t>((v >> 8)  & 0xFF),
            static_cast<uint8_t>((v >> 16) & 0xFF),
            static_cast<uint8_t>((v >> 24) & 0xFF)
        };
        return writeBytes(tmp, 4);
    }
    bool write(int32_t v)             { return write(static_cast<uint32_t>(v)); }

    bool write(float f) {
        static_assert(sizeof(float) == 4, "float must be 32-bit");
        uint32_t tmp;
        memcpy(&tmp, &f, 4);
        return write(tmp);
    }

    // For single ASCII char
    bool write(char c)                { return write(static_cast<uint8_t>(c)); }

    // ------------------------------------------------------------------
    // Length-prefixed String (u8 length, clip at 255)
    // [len:u8][bytes...]
    // ------------------------------------------------------------------
    bool write(const String& s) {
        size_t L = s.length();
        if (L > 255) L = 255;
        if (!write(static_cast<uint8_t>(L))) return false;
        return writeBytes(s.c_str(), L);
    }

    // Write from char* + known length (len clipped to 255 for u8 prefix)
    bool write(const char* s, size_t len) {
        if (len > 255) len = 255;
        if (!write(static_cast<uint8_t>(len))) return false;
        return writeBytes(s, len);
    }

private:
    uint8_t* buf_;
    size_t   cap_;
    size_t   pos_;
    bool     overflow_;
};


// ------------------------------------------------------------------
// PacketReader: cursor-based decoder from const buffer.
// ------------------------------------------------------------------
class PacketReader {
public:
    PacketReader(const uint8_t* buf, size_t len)
    : buf_(buf), len_(len), pos_(0) {}

    void reset(const uint8_t* buf, size_t len) {
        buf_ = buf;
        len_ = len;
        pos_ = 0;
    }

    size_t size() const      { return len_; }
    size_t position() const  { return pos_; }
    size_t remaining() const { return (pos_ >= len_) ? 0 : len_ - pos_; }
    bool   atEnd() const     { return pos_ >= len_; }

    // Skip N bytes (returns false if not enough)
    bool skip(size_t n) {
        if (pos_ + n > len_) return false;
        pos_ += n;
        return true;
    }

    // ------------------------------------------------------------------
    // Core raw reader
    // ------------------------------------------------------------------
    bool readBytes(const uint8_t*& ptr, size_t n) {
        if (pos_ + n > len_) return false;
        ptr = buf_ + pos_;
        pos_ += n;
        return true;
    }
    bool readCopy(void* dst, size_t n) {
        if (pos_ + n > len_) return false;
        memcpy(dst, buf_ + pos_, n);
        pos_ += n;
        return true;
    }

    // ------------------------------------------------------------------
    // Primitive overloads (little-endian)
    // ------------------------------------------------------------------
    bool read(uint8_t& v) {
        if (pos_ + 1 > len_) return false;
        v = buf_[pos_++];
        return true;
    }
    bool read(int8_t& v) {
        uint8_t u;
        if (!read(u)) return false;
        v = static_cast<int8_t>(u);
        return true;
    }
    bool read(bool& v) {
        uint8_t u;
        if (!read(u)) return false;
        v = (u != 0);
        return true;
    }
    bool read(uint16_t& v) {
        if (pos_ + 2 > len_) return false;
        v  = static_cast<uint16_t>(buf_[pos_]);
        v |= static_cast<uint16_t>(buf_[pos_+1]) << 8;
        pos_ += 2;
        return true;
    }
    bool read(int16_t& v) {
        uint16_t tmp;
        if (!read(tmp)) return false;
        v = static_cast<int16_t>(tmp);
        return true;
    }
    bool read(uint32_t& v) {
        if (pos_ + 4 > len_) return false;
        v  = static_cast<uint32_t>(buf_[pos_]);
        v |= static_cast<uint32_t>(buf_[pos_+1]) << 8;
        v |= static_cast<uint32_t>(buf_[pos_+2]) << 16;
        v |= static_cast<uint32_t>(buf_[pos_+3]) << 24;
        pos_ += 4;
        return true;
    }
    bool read(int32_t& v) {
        uint32_t tmp;
        if (!read(tmp)) return false;
        v = static_cast<int32_t>(tmp);
        return true;
    }
    bool read(float& f) {
        uint32_t tmp;
        if (!read(tmp)) return false;
        memcpy(&f, &tmp, 4);
        return true;
    }
    bool read(char& c) {
        uint8_t u;
        if (!read(u)) return false;
        c = static_cast<char>(u);
        return true;
    }

    // ------------------------------------------------------------------
    // Length-prefixed string (u8 len + bytes)
    // ------------------------------------------------------------------
    bool read(String& out) {
        uint8_t L;
        if (!read(L)) return false;
        if (pos_ + L > len_) return false;
        out = String();
        out.reserve(L);
        for (uint8_t i = 0; i < L; ++i) {
            out += static_cast<char>(buf_[pos_ + i]);
        }
        pos_ += L;
        return true;
    }

private:
    const uint8_t* buf_;
    size_t         len_;
    size_t         pos_;
};

#endif // PACKET_IO_H