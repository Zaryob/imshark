#include "clipboard.h"

#include <algorithm>
#include <cstdio>

std::string ui::fieldValue(const packet::Field &field) {
    const auto pos = field.text.find(": ");
    return pos == std::string::npos ? field.text : field.text.substr(pos + 2);
}

std::string ui::bytesToHex(const std::vector<char> &data, size_t offset, size_t length) {
    std::string out;
    if (offset >= data.size()) return out;
    const size_t end = offset + std::min(length, data.size() - offset);
    for (size_t i = offset; i < end; ++i) {
        char buf[4];
        std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned char>(data[i]));
        if (!out.empty()) out += ' ';
        out += buf;
    }
    return out;
}

std::string ui::bytesToAscii(const std::vector<char> &data, size_t offset, size_t length) {
    std::string out;
    if (offset >= data.size()) return out;
    const size_t end = offset + std::min(length, data.size() - offset);
    for (size_t i = offset; i < end; ++i) {
        const auto c = static_cast<unsigned char>(data[i]);
        out += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
    }
    return out;
}

std::string ui::hexDump(const std::vector<char> &data) {
    std::string out;
    for (size_t row = 0; row < data.size(); row += 16) {
        char head[2 * sizeof(size_t) + 3];
        std::snprintf(head, sizeof(head), "%06zx  ", row);
        out += head;
        std::string hex = bytesToHex(data, row, 16);
        hex.resize(16 * 3 - 1, ' '); // pad the last line so the ASCII column lines up
        out += hex + "  " + bytesToAscii(data, row, 16) + "\n";
    }
    return out;
}

std::string ui::summaryRow(const packet::PacketInfo &p) {
    char time[32];
    std::snprintf(time, sizeof(time), "%.6f", p.time);
    return std::to_string(p.number) + "\t" + time + "\t" + p.source + "\t" + p.destination + "\t" + p.protocol + "\t" +
           std::to_string(p.frame_length) + "\t" + p.info;
}
