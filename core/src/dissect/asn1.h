#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "reader.h"

namespace dissect {

/// ASN.1 BER / DER Tag Sınıfları (X.690 §8.1.2)
namespace asn1 {
    enum Class : uint8_t {
        Universal = 0,
        Application = 1,
        ContextSpecific = 2,
        Private = 3
    };

    namespace tag {
        constexpr uint32_t Eoc = 0;
        constexpr uint32_t Boolean = 1;
        constexpr uint32_t Integer = 2;
        constexpr uint32_t BitString = 3;
        constexpr uint32_t OctetString = 4;
        constexpr uint32_t Null = 5;
        constexpr uint32_t Oid = 6;
        constexpr uint32_t ObjectDescriptor = 7;
        constexpr uint32_t External = 8;
        constexpr uint32_t Real = 9;
        constexpr uint32_t Enumerated = 10;
        constexpr uint32_t Utf8String = 12;
        constexpr uint32_t Sequence = 16;       // 0x10; constructed ise 0x30
        constexpr uint32_t Set = 17;            // 0x11; constructed ise 0x31
        constexpr uint32_t NumericString = 18;
        constexpr uint32_t PrintableString = 19;
        constexpr uint32_t TeletexString = 20;
        constexpr uint32_t Ia5String = 22;
        constexpr uint32_t UtcTime = 23;        // 0x17
        constexpr uint32_t GeneralizedTime = 24;// 0x18
    } // namespace tag
} // namespace asn1

/// Sınır denetimli ASN.1 BER/DER TLV yapısı
struct BerTlv {
    uint8_t rawTag = 0;           // İlk bayt: class(2), constructed(1), tag_number(5)
    uint8_t tagClass = 0;         // 0: Universal, 1: Application, 2: Context, 3: Private
    bool constructed = false;     // true: constructed, false: primitive
    uint32_t tagNumber = 0;       // Tag numarası (çok baytlı tag'ler dahil)
    bool indefinite = false;      // true: belirsiz uzunluk (0x80 .. EOC)
    const uint8_t *value = nullptr;
    size_t length = 0;            // Değer bayt sayısı
    size_t headerLength = 0;      // Tag + Length bayt sayısı
    size_t total = 0;             // Başlık + Değer (+ varsa EOC) toplam bayt sayısı

    bool isUniversal(uint32_t num) const { return tagClass == asn1::Universal && tagNumber == num; }
    bool isContext(uint32_t num) const { return tagClass == asn1::ContextSpecific && tagNumber == num; }
    bool isApplication(uint32_t num) const { return tagClass == asn1::Application && tagNumber == num; }

    /// INTEGER (ikiye tümleyen, 64-bit sınırlı işaretli tamsayı)
    bool asInt64(int64_t &out) const {
        if (length == 0 || length > 8 || !value) return false;
        int64_t val = (value[0] & 0x80) ? -1 : 0;
        for (size_t i = 0; i < length; ++i) {
            val = (val << 8) | static_cast<uint8_t>(value[i]);
        }
        out = val;
        return true;
    }

    /// INTEGER / Unsigned (SNMP Counter/Gauge/TimeTicks vb. için)
    bool asUint64(uint64_t &out) const {
        if (length == 0 || !value) return false;
        size_t start = 0;
        // Pozitifliği korumak için eklenen baştaki 0x00 baytı
        if (length > 1 && value[0] == 0x00) {
            start = 1;
        }
        if (length - start > 8) return false;
        uint64_t val = 0;
        for (size_t i = start; i < length; ++i) {
            val = (val << 8) | static_cast<uint64_t>(value[i]);
        }
        out = val;
        return true;
    }

    /// OID -> "1.3.6.1.4.1..." metnine dönüştürür
    std::string asOid() const {
        if (length == 0 || !value) return {};
        std::string s;
        // İlk bayt X * 40 + Y kuralı
        const unsigned int b0 = value[0];
        unsigned int first = b0 / 40;
        unsigned int second = b0 % 40;
        if (first > 2) {
            first = 2;
            second = b0 - 80;
        }
        s = std::to_string(first) + "." + std::to_string(second);

        // Kalan alt tanımlayıcılar (sub-identifiers): 7-bit değişken uzunluklu kodlama
        uint64_t subId = 0;
        for (size_t i = 1; i < length; ++i) {
            const uint8_t b = value[i];
            // Taşma koruması: subId << 7 taşmamalı
            if (subId > (UINT64_MAX >> 7)) return {};
            subId = (subId << 7) | (b & 0x7f);
            if ((b & 0x80) == 0) {
                s += "." + std::to_string(subId);
                subId = 0;
            }
        }
        if (subId != 0) return {}; // Eksik son bayt (0x80 biti açık kalmış)
        return s;
    }

    /// OCTET STRING / metin içeriğini std::string olarak döndürür
    std::string asString() const {
        if (length == 0 || !value) return {};
        return std::string(reinterpret_cast<const char *>(value), length);
    }

    /// Yazdırılabilir olmayan karakterleri '?' ile değiştirerek gösterir
    std::string asPrintable() const {
        if (length == 0 || !value) return {};
        std::string s;
        s.reserve(length);
        for (size_t i = 0; i < length; ++i) {
            const unsigned char c = value[i];
            s += (c >= 32 && c < 127) ? static_cast<char>(c) : '?';
        }
        return s;
    }

    /// Hexadecimal metin (örn. seri numarası)
    std::string asHexString() const {
        if (length == 0 || !value) return {};
        std::string s;
        s.reserve(length * 2);
        for (size_t i = 0; i < length; ++i) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02x", value[i]);
            s += buf;
        }
        return s;
    }
};

/// Tek bir BER TLV kaydını okur.
/// reader'ın geçerli pozisyonundan okur; başarılıysa reader pozisyonunu TLV'nin sonuna ilerletir.
/// maxDepth: iç içe çağrı derinlik sınırı (varsayılan 32).
inline bool readBerTlv(ByteReader &r, BerTlv &out, int maxDepth = 32) {
    if (maxDepth <= 0 || !r.ok() || r.remaining() < 2) return false;

    const size_t startOffset = r.offset();
    const uint8_t rawTag = r.u8();
    out.rawTag = rawTag;
    out.tagClass = (rawTag >> 6) & 0x03;
    out.constructed = (rawTag & 0x20) != 0;

    uint32_t tagNum = rawTag & 0x1f;
    if (tagNum == 0x1f) {
        // Çok baytlı tag numarası
        tagNum = 0;
        bool more = true;
        int count = 0;
        while (more) {
            if (!r.ok() || r.remaining() < 1 || count >= 5) return false;
            const uint8_t b = r.u8();
            count++;
            more = (b & 0x80) != 0;
            if (tagNum > (0x0fffffffu >> 7)) return false; // Taşma koruması
            tagNum = (tagNum << 7) | (b & 0x7f);
        }
    }
    out.tagNumber = tagNum;

    // Uzunluk alanı okuma (X.690 §8.1.3)
    if (!r.ok() || r.remaining() < 1) return false;
    const uint8_t lenByte = r.u8();

    if (lenByte < 0x80) {
        // Kısa biçim: 0..127
        out.indefinite = false;
        out.length = lenByte;
    } else if (lenByte == 0x80) {
        // Belirsiz biçim (Indefinite length): yalnızca constructed tipler için geçerlidir
        if (!out.constructed) return false;
        out.indefinite = true;
    } else {
        // Uzun biçim: lenByte & 0x7f = uzunluk baytı sayısı
        const size_t count = lenByte & 0x7f;
        if (count == 0 || count > 4 || r.remaining() < count) return false; // En fazla 4 bayt uzunluk
        size_t len = 0;
        for (size_t i = 0; i < count; ++i) {
            len = (len << 8) | r.u8();
        }
        out.indefinite = false;
        out.length = len;
    }

    if (!out.indefinite) {
        if (r.remaining() < out.length) return false;
        out.value = r.current();
        r.skip(out.length);
        out.headerLength = (out.value - r.data()) - startOffset;
        out.total = out.headerLength + out.length;
        return true;
    }

    // Belirsiz uzunluk (Indefinite length): EOC (0x00 0x00) görene kadar alt TLV'leri tara
    out.value = r.current();
    out.headerLength = (out.value - r.data()) - startOffset;

    size_t contentLen = 0;
    while (true) {
        if (!r.ok() || r.remaining() < 2) return false;
        if (r.peek_u8() == 0x00 && r.data()[r.offset() + 1] == 0x00) {
            // EOC (End-Of-Contents) bulundu
            r.skip(2);
            break;
        }
        BerTlv child;
        if (!readBerTlv(r, child, maxDepth - 1)) return false;
        contentLen += child.total;
    }

    out.length = contentLen;
    out.total = out.headerLength + out.length + 2; // + 2 bayt EOC
    return true;
}

/// Kolaylık fonksiyonu: ham arabellekten tek TLV okuma
inline bool readBerTlv(const uint8_t *p, size_t n, BerTlv &out, int maxDepth = 32) {
    if (!p || n < 2) return false;
    ByteReader r(p, n);
    return readBerTlv(r, out, maxDepth);
}

/// Bir constructed TLV'nin alt elemanları üzerinde f(childTlv) çağırır.
/// İçerik bozuksa false döner; derinlik sınırı 32'dir.
template<typename F>
inline bool eachChild(const BerTlv &parent, F &&f, int maxDepth = 32) {
    if (!parent.constructed || !parent.value || maxDepth <= 0) return false;
    ByteReader r(parent.value, parent.length);
    while (r.remaining() > 0) {
        BerTlv c;
        if (!readBerTlv(r, c, maxDepth - 1)) return false;
        f(c);
    }
    return true;
}

} // namespace dissect
