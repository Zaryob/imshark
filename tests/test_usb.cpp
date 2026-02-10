#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/usb.h>
#include "support.h"

using support::parse;
using namespace dissect;

namespace {

packet::PacketInfo parseLinkPacket(uint32_t linkType, const std::vector<uint8_t> &data) {
    packet::PacketParser parser;
    packet::PacketInfo pack(1);
    pack.link_type = linkType;
    std::vector<char> raw(data.begin(), data.end());
    parser.parsePacket(pack, raw, dissect::ParseMode::Full);
    return pack;
}

} // namespace

TEST(Usb, LinuxUsbControlSetupPacket) {
    // 48 bytes usbmon header:
    // urbId: 0x1122334455667788 (8 bytes)
    // eventType: 'S' (Submit)
    // transferType: 2 (CONTROL)
    // endpoint: 0x80 (IN, ep 0)
    // device: 3
    // busId: 1
    // setupFlag: 0 (present)
    // dataFlag: 0
    // tsSec: 0, tsUsec: 0
    // status: 0
    // urbLen: 18, dataLen: 0
    // setup packet (8 bytes): bmReqType 0x80, bReq 6 (GET_DESCRIPTOR), wValue 0x0100 (DEVICE), wIndex 0, wLength 18
    std::vector<uint8_t> pdu = {
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // urbId
        'S', // eventType
        2,   // transferType = CONTROL
        0x80, // endpoint IN (0x80)
        3,   // device 3
        0x01, 0x00, // busId 1
        0x00, // setupFlag (present)
        0x00, // dataFlag
        0, 0, 0, 0, 0, 0, 0, 0, // tsSec
        0, 0, 0, 0,             // tsUsec
        0, 0, 0, 0,             // status
        18, 0, 0, 0,            // urbLen
        0, 0, 0, 0,             // dataLen
        // Setup packet (8 bytes):
        0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00
    };

    auto pkt = parseLinkPacket(189, pdu);

    EXPECT_EQ(pkt.protocol, "USB");
    EXPECT_EQ(pkt.app_type, 2); // CONTROL
    EXPECT_EQ(pkt.source, "1.3");
    EXPECT_EQ(pkt.destination, "host");
    EXPECT_NE(pkt.info.find("URB Submit CONTROL IN"), std::string::npos);
    EXPECT_NE(pkt.info.find("Dev 3"), std::string::npos);
}

TEST(Usb, LinuxUsbControlCompleteWithDescriptor) {
    // 48 bytes usbmon header + 18 bytes standard Device Descriptor
    std::vector<uint8_t> pdu = {
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // urbId
        'C', // eventType (Complete)
        2,   // transferType = CONTROL
        0x80, // endpoint IN
        3,   // device 3
        0x01, 0x00, // busId 1
        0x01, // setupFlag (none in complete)
        0x00, // dataFlag (present)
        0, 0, 0, 0, 0, 0, 0, 0, // tsSec
        0, 0, 0, 0,             // tsUsec
        0, 0, 0, 0,             // status
        18, 0, 0, 0,            // urbLen
        18, 0, 0, 0,            // dataLen (18)
        0, 0, 0, 0, 0, 0, 0, 0, // padding setup
        // Device Descriptor (18 bytes):
        18, 1, // bLength 18, bDescriptorType 1 (DEVICE)
        0x00, 0x02, // bcdUSB 2.00
        0x00, 0x00, 0x00, // class, subclass, proto
        64,   // bMaxPacketSize0
        0x86, 0x80, // idVendor 0x8086
        0x34, 0x12, // idProduct 0x1234
        0x00, 0x01, // bcdDevice 1.00
        1, 2, 3, 1  // strings, numConfigs
    };

    auto pkt = parseLinkPacket(189, pdu);

    EXPECT_EQ(pkt.protocol, "USB");
    EXPECT_NE(pkt.info.find("URB Complete CONTROL IN"), std::string::npos);
    EXPECT_NE(pkt.info.find("[18 bytes]"), std::string::npos);
}

TEST(Usb, UsbPcapBulkTransfer) {
    // USBPcap Header (28 bytes)
    // headerLen: 28
    // irpId: 0x1234
    // usbdStatus: 0
    // function: 0
    // info: 1 (FDO -> PDO: IN)
    // busId: 1
    // device: 4
    // endpoint: 0x81 (IN ep 1)
    // transferType: 3 (BULK)
    // dataLen: 64
    std::vector<uint8_t> pdu = {
        28, 0, // headerLen
        0x34, 0x12, 0, 0, 0, 0, 0, 0, // irpId
        0, 0, 0, 0, // usbdStatus
        0, 0,       // function
        1,          // info = IN
        1, 0,       // busId
        4, 0,       // device
        0x81,       // endpoint
        3,          // transferType = BULK
        64, 0, 0, 0 // dataLen
    };
    // 64 bytes data
    for (int i = 0; i < 64; ++i) pdu.push_back(static_cast<uint8_t>(i));

    auto pkt = parseLinkPacket(249, pdu);

    EXPECT_EQ(pkt.protocol, "USB");
    EXPECT_EQ(pkt.app_type, 3); // BULK
    EXPECT_EQ(pkt.source, "1.4");
    EXPECT_EQ(pkt.destination, "host");
    EXPECT_NE(pkt.info.find("USBPcap BULK IN"), std::string::npos);
    EXPECT_NE(pkt.info.find("[64 bytes]"), std::string::npos);
}
