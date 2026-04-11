#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/industrial.h>
#include "support.h"
#include "frame_sweep.h"

using namespace dissect;
using framesweep::Bytes;

namespace {

Bytes cat(Bytes a, const Bytes &b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

Bytes tcpSegment(uint16_t sport, uint16_t dport, const Bytes &payload) {
    Bytes h = {static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff), static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
               0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0x20, 0x00, 0, 0, 0, 0};
    return cat(h, payload);
}

// Ethernet (14) + IPv4 (20) + TCP (20): the application data starts at frame offset 54
Bytes overTcp(uint16_t sport, uint16_t dport, const Bytes &payload) {
    return framesweep::ethernet(0x0800, framesweep::ipv4Packet(6, tcpSegment(sport, dport, payload)));
}

// Ethernet (14) + IPv4 (20) + UDP (8): data at offset 42
Bytes overUdp(uint16_t port, const Bytes &payload) {
    return framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(40000, port, payload)));
}

packet::PacketInfo parseLinkPacket(uint32_t linkType, const Bytes &data) { return framesweep::parseEthernet(data, linkType); }

const packet::Field *findNode(const std::vector<packet::Field> &nodes, const std::string &prefix) {
    for (const auto &n: nodes) {
        if (n.text.rfind(prefix, 0) == 0) return &n;
        if (auto *c = findNode(n.children, prefix)) return c;
    }
    return nullptr;
}

// Modbus Application Protocol Specification V1.1b3, section 6.3 (Read Holding Registers): request "start address 0x006B,
// 3 registers" (03 00 6B 00 03), response "2B 00 00 00 64" for the values 555, 0, 100; the MBAP header is transaction id,
// protocol id 0, length (unit id + PDU) and unit id.
const Bytes kModbusRequest = {0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6b, 0x00, 0x03};
const Bytes kModbusResponse = {0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x11, 0x03, 0x06, 0x02, 0x2b, 0x00, 0x00, 0x00, 0x64};
const Bytes kModbusException = {0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x11, 0x83, 0x02};

// IEEE 1815 (DNP3) data link frame: 05 64, LEN = 5 + user data bytes, control, destination (LE), source (LE), CRC-16/DNP
// of those 8 bytes (little endian), then the user data followed by its own CRC. The CRCs come from an independent
// bitwise CRC-16/DNP written in Python (poly 0x3D65 reflected, init 0, xorout 0xFFFF; it reproduces the catalogue check
// value 0xEA82 for "123456789"): header 05 64 08 c4 01 00 02 00 -> 0x0d39, data c0 c0 01 -> 0xa06d,
// header 05 64 0a 44 02 00 01 00 -> 0xf010, data c0 c0 81 00 00 -> 0xe89c. The dissector does not verify them.
const Bytes kDnp3Read = {0x05, 0x64, 0x08, 0xc4, 0x01, 0x00, 0x02, 0x00, 0x39, 0x0d,
                         0xc0, 0xc0, 0x01, 0x6d, 0xa0};  // transport C0, application control C0, function 1 (Read)
const Bytes kDnp3Response = {0x05, 0x64, 0x0a, 0x44, 0x02, 0x00, 0x01, 0x00, 0x10, 0xf0,
                             0xc0, 0xc0, 0x81, 0x00, 0x00, 0x9c, 0xe8};  // function 0x81 (Response) + 2 IIN bytes

// SocketCAN classic frame: can_id (BE) with EFF/RTR/ERR flags, can_dlc, 3 padding bytes, 8 data bytes
Bytes canFrame(uint32_t id, uint8_t dlc, const Bytes &data) {
    Bytes b = {static_cast<uint8_t>(id >> 24), static_cast<uint8_t>(id >> 16), static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id), dlc, 0, 0, 0};
    Bytes d = data;
    d.resize(8, 0);
    return cat(b, d);
}

} // namespace

TEST(Industrial, ModbusSpecExamples) {
    const auto req = framesweep::parseEthernet(overTcp(54321, 502, kModbusRequest));
    EXPECT_EQ(req.protocol, "Modbus");
    EXPECT_EQ(req.app_type, 3);
    EXPECT_EQ(req.info, "Read Holding Registers (TransID 1, Unit 17)");
    const auto *unit = findNode(req.fields, "Unit ID: 17");
    ASSERT_NE(unit, nullptr);
    EXPECT_EQ(unit->offset, 60u);   // 54 + 6
    const auto *fn = findNode(req.fields, "Function Code: Read Holding Registers (3)");
    ASSERT_NE(fn, nullptr);
    EXPECT_EQ(fn->offset, 61u);
    const auto *len = findNode(req.fields, "Length: 6");
    ASSERT_NE(len, nullptr);
    EXPECT_EQ(len->offset, 58u);

    const auto resp = framesweep::parseEthernet(overTcp(502, 54321, kModbusResponse));
    EXPECT_EQ(resp.protocol, "Modbus");
    EXPECT_EQ(resp.info, "Read Holding Registers (TransID 1, Unit 17)");
    EXPECT_EQ(resp.fields.back().length, 15u);

    const auto exc = framesweep::parseEthernet(overTcp(502, 54321, kModbusException));
    EXPECT_EQ(exc.info, "Exception: Read Holding Registers (Code 2)");
    EXPECT_EQ(exc.app_code, 2);
    EXPECT_EQ(exc.app_type, 0x83);
}

TEST(Industrial, ModbusRejectsForeignProtocolIdsAndFlagsInconsistentLengths) {
    Bytes foreign = kModbusRequest;
    foreign[3] = 1;   // protocol id 1: not Modbus
    EXPECT_NE(framesweep::parseEthernet(overTcp(54321, 502, foreign)).protocol, "Modbus");
    // length field promises 0x40 bytes, 6 are there
    Bytes tooLong = kModbusRequest;
    tooLong[5] = 0x40;
    const auto big = framesweep::parseEthernet(overTcp(54321, 502, tooLong));
    EXPECT_EQ(big.protocol, "Modbus");
    EXPECT_NE(big.info.find("[Malformed Packet"), std::string::npos) << big.info;
    // length 1 leaves no room for a function code
    Bytes noFn = kModbusRequest;
    noFn[5] = 0x01;
    EXPECT_NE(framesweep::parseEthernet(overTcp(54321, 502, noFn)).info.find("[Malformed Packet"), std::string::npos);
}

TEST(Industrial, ModbusStreamFramer) {
    const auto req = frameModbus(reinterpret_cast<const char *>(kModbusRequest.data()), kModbusRequest.size());
    EXPECT_EQ(req.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(req.length, 12u);
    EXPECT_EQ(frameModbus(reinterpret_cast<const char *>(kModbusRequest.data()), 11).kind, StreamFrame::Kind::NeedMore);
    const Bytes two = cat(kModbusRequest, kModbusException);
    EXPECT_EQ(frameModbus(reinterpret_cast<const char *>(two.data()), two.size()).length, 12u);
    Bytes foreign = kModbusRequest;
    foreign[2] = 0x01;
    EXPECT_EQ(frameModbus(reinterpret_cast<const char *>(foreign.data()), foreign.size()).kind, StreamFrame::Kind::Reject);
    Bytes huge = kModbusRequest;
    huge[4] = 0xff;
    EXPECT_EQ(frameModbus(reinterpret_cast<const char *>(huge.data()), huge.size()).kind, StreamFrame::Kind::Reject);
}

TEST(Industrial, Dnp3ReadRequestAndResponse) {
    const auto req = framesweep::parseEthernet(overTcp(54321, 20000, kDnp3Read));
    EXPECT_EQ(req.protocol, "DNP3");
    EXPECT_EQ(req.info, "DNP3 (Src 2 -> Dst 1), Read");
    EXPECT_EQ(req.app_type, 1);
    // the IP addresses stay in the packet list (the link addresses are in the Info and the details)
    EXPECT_EQ(req.source, "10.0.0.1");
    EXPECT_EQ(req.destination, "10.0.0.2");
    const auto *src = findNode(req.fields, "Source: 2");
    ASSERT_NE(src, nullptr);
    EXPECT_EQ(src->offset, 60u);
    ASSERT_NE(findNode(req.fields, "Header CRC: 0x0d39"), nullptr);
    const auto *fc = findNode(req.fields, "Application Function Code: 1");
    ASSERT_NE(fc, nullptr);
    EXPECT_EQ(fc->offset, 66u);

    const auto resp = framesweep::parseEthernet(overUdp(20000, kDnp3Response));
    EXPECT_EQ(resp.protocol, "DNP3");
    EXPECT_EQ(resp.info, "DNP3 (Src 1 -> Dst 2), Response");
    EXPECT_EQ(resp.app_type, 0x81);
}

TEST(Industrial, Dnp3WithoutApplicationBytesShowsNoFunctionCode) {
    // LEN 6 = control + addresses + only the transport header byte: the byte at offset 11 is the block CRC, not a function code
    const Bytes transportOnly = {0x05, 0x64, 0x06, 0xc4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0x01, 0x00};
    const auto pkt = framesweep::parseEthernet(overTcp(54321, 20000, transportOnly));
    EXPECT_EQ(pkt.protocol, "DNP3");
    EXPECT_EQ(pkt.info, "DNP3 (Src 2 -> Dst 1)");
    EXPECT_EQ(pkt.app_type, 0);
}

TEST(Industrial, Dnp3StreamFramer) {
    auto frame = [](const Bytes &b, size_t n) { return frameDnp3(reinterpret_cast<const char *>(b.data()), n); };
    EXPECT_EQ(frame(kDnp3Read, kDnp3Read.size()).kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(frame(kDnp3Read, kDnp3Read.size()).length, 15u);          // 10 + 3 user bytes + 1 block CRC
    EXPECT_EQ(frame(kDnp3Read, 14).kind, StreamFrame::Kind::NeedMore);
    EXPECT_EQ(frame(kDnp3Response, kDnp3Response.size()).length, 17u);  // 10 + 5 + 2
    // 20 user bytes: two blocks (16 + 4) with a CRC each: 10 + 20 + 4 bytes
    Bytes long20 = {0x05, 0x64, 25, 0xc4, 1, 0, 2, 0, 0, 0};
    long20.resize(34, 0);
    EXPECT_EQ(frame(long20, long20.size()).length, 34u);
    Bytes bad = kDnp3Read;
    bad[0] = 0x06;
    EXPECT_EQ(frame(bad, bad.size()).kind, StreamFrame::Kind::Reject);
    Bytes shortLen = kDnp3Read;
    shortLen[2] = 4;
    EXPECT_EQ(frame(shortLen, shortLen.size()).kind, StreamFrame::Kind::Reject);
}

TEST(Industrial, SocketCanClassicFrames) {
    const auto std11 = parseLinkPacket(227, canFrame(0x123, 4, {0xaa, 0xbb, 0xcc, 0xdd}));
    EXPECT_EQ(std11.protocol, "CAN");
    EXPECT_EQ(std11.app_type, 0x123);
    EXPECT_EQ(std11.info, "CAN ID: 0x123 DLC: 4 Data: aa bb cc dd");
    const auto *id = findNode(std11.fields, "CAN ID: 0x123 (Standard 11-bit)");
    ASSERT_NE(id, nullptr);
    EXPECT_EQ(id->offset, 0u);
    const auto *data = findNode(std11.fields, "Data (4 bytes)");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->offset, 8u);

    // extended frame: EFF flag (bit 31) + 29-bit id 0x12345678; the id does not fit app_type, the high bits go to app_code
    const auto ext = parseLinkPacket(227, canFrame(0x80000000u | 0x12345678u, 2, {0xde, 0xad}));
    EXPECT_EQ(ext.info, "CAN ID: 0x12345678 DLC: 2 Data: de ad");
    EXPECT_EQ(ext.app_type, 0x5678);
    EXPECT_EQ(ext.app_code, 0x1234);
    ASSERT_NE(findNode(ext.fields, "CAN ID: 0x12345678 (Extended 29-bit)"), nullptr);

    // remote transmission request carries no data; error frame flag
    EXPECT_EQ(parseLinkPacket(227, canFrame(0x40000000u | 0x7ff, 8, {})).info, "CAN ID: 0x7ff DLC: 8 [RTR]");
    EXPECT_EQ(parseLinkPacket(227, canFrame(0x20000000u | 0x001, 0, {})).info, "CAN ID: 0x001 DLC: 0 [ERROR]");
    // a DLC above 8 never reads past the 8 data bytes of a classic frame
    EXPECT_EQ(parseLinkPacket(227, canFrame(0x10, 15, {1, 2, 3, 4, 5, 6, 7, 8})).info, "CAN ID: 0x010 DLC: 15 Data: 01 02 03 04 05 06 07 08");
    EXPECT_NE(parseLinkPacket(227, Bytes(15, 0)).info.find("[Malformed Packet"), std::string::npos);
}

TEST(Industrial, SocketCanFdFrameCarriesUpToSixtyFourBytes) {
    // struct canfd_frame: can_id, len, flags (BRS = 1), 2 reserved bytes, 64 data bytes = 72 bytes
    Bytes fd = {0x00, 0x00, 0x07, 0xff, 12, 0x01, 0, 0};
    for (int i = 0; i < 64; ++i) fd.push_back(static_cast<uint8_t>(i));
    ASSERT_EQ(fd.size(), 72u);
    const auto pkt = parseLinkPacket(227, fd);
    EXPECT_EQ(pkt.protocol, "CAN FD");
    EXPECT_EQ(pkt.info, "CAN ID: 0x7ff DLC: 12 Data: 00 01 02 03 04 05 06 07 08 09 0a 0b");
    const auto *data = findNode(pkt.fields, "Data (12 bytes)");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->length, 12u);
    ASSERT_NE(findNode(pkt.fields, "FD Flags: 0x01"), nullptr);
    fd[4] = 64;
    EXPECT_NE(parseLinkPacket(227, fd).info.find("..."), std::string::npos) << "long data is abbreviated in the Info column";
}

TEST(Industrial, TruncationAndMutationStayInsideTheFrame) {
    framesweep::sweep(overTcp(54321, 502, kModbusRequest), 51);
    framesweep::sweep(overTcp(502, 54321, kModbusResponse), 52);
    framesweep::sweep(overTcp(502, 54321, kModbusException), 53);
    framesweep::sweep(overTcp(54321, 20000, kDnp3Read), 54);
    framesweep::sweep(overUdp(20000, kDnp3Response), 55);
    framesweep::sweep(canFrame(0x80000000u | 0x12345678u, 4, {1, 2, 3, 4}), 56, 400, 227);
    Bytes fd = {0x00, 0x00, 0x07, 0xff, 12, 0x01, 0, 0};
    fd.resize(72, 7);
    framesweep::sweep(fd, 57, 400, 227);
}

TEST(Industrial, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"Modbus", "DNP3", "CAN", "CAN FD"});
}
