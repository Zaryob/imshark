#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/usb.h>
#include "support.h"
#include "frame_sweep.h"

using namespace dissect;
using framesweep::Bytes;

namespace {

// Layouts: Linux Documentation/usb/usbmon.rst (struct mon_bin_hdr, 48 bytes), USB 2.0 specification chapter 9
// (setup packet 9.3, standard descriptors 9.6) and the USBPcap capture format (27 byte header + stage byte).

Bytes cat(Bytes a, const Bytes &b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

void putLe(Bytes &b, uint64_t v, int n) {
    for (int i = 0; i < n; ++i) b.push_back(i < 8 ? static_cast<uint8_t>(v >> (8 * i)) : 0);
}

// usbmon header; `setup` (8 bytes) is present when given, `payload` is the captured data (dataLen = its size)
Bytes usbmon(uint64_t urbId, char event, uint8_t xfer, uint8_t endpoint, uint8_t device, uint16_t bus, const Bytes &setup,
             const Bytes &payload, int32_t status = 0, bool mmapped = false) {
    Bytes b;
    putLe(b, urbId, 8);
    b.push_back(static_cast<uint8_t>(event));
    b.push_back(xfer);
    b.push_back(endpoint);
    b.push_back(device);
    putLe(b, bus, 2);
    b.push_back(setup.empty() ? '-' : 0);          // flag_setup: 0 = setup packet present
    b.push_back(payload.empty() ? '<' : 0);        // flag_data: 0 = data present
    putLe(b, 0, 8);                                // ts_sec
    putLe(b, 0, 4);                                // ts_usec
    putLe(b, static_cast<uint32_t>(status), 4);
    putLe(b, payload.size(), 4);                   // length
    putLe(b, payload.size(), 4);                   // len_cap
    Bytes s = setup.empty() ? Bytes(8, 0) : setup;
    b.insert(b.end(), s.begin(), s.end());
    if (mmapped) putLe(b, 0, 16);                  // interval, start_frame, xfer_flags, ndesc
    return cat(b, payload);
}

// Setup packet: bmRequestType, bRequest, wValue, wIndex, wLength (little endian)
Bytes setupPacket(uint8_t type, uint8_t request, uint16_t value, uint16_t index, uint16_t length) {
    Bytes b = {type, request};
    putLe(b, value, 2);
    putLe(b, index, 2);
    putLe(b, length, 2);
    return b;
}

const Bytes kGetDeviceDescriptor = setupPacket(0x80, 6, 0x0100, 0, 18);
const Bytes kGetConfigDescriptor = setupPacket(0x80, 6, 0x0200, 0, 34);

// Device descriptor of a Linux root hub (USB 2.0 9.6.1): bcdUSB 2.00, hub class, ep0 packet size 64, 1d6b:0002, bcdDevice 5.10
const Bytes kDeviceDescriptor = {18, 1, 0x00, 0x02, 9, 0, 1, 64, 0x6b, 0x1d, 0x02, 0x00, 0x10, 0x05, 3, 2, 1, 1};
// Configuration (9.6.3, wTotalLength 25), interface (9.6.5) and interrupt IN endpoint 1 (9.6.6) descriptors
const Bytes kConfigChain = {9, 2, 25, 0, 1, 1, 0, 0xe0, 0,
                            9, 4, 0, 0, 1, 9, 0, 0, 0,
                            7, 5, 0x81, 3, 4, 0, 12};

const packet::Field *findNode(const std::vector<packet::Field> &nodes, const std::string &prefix) {
    for (const auto &n: nodes) {
        if (n.text.rfind(prefix, 0) == 0) return &n;
        if (auto *c = findNode(n.children, prefix)) return c;
    }
    return nullptr;
}

int countLayers(const packet::PacketInfo &p, const std::string &prefix) {
    int n = 0;
    for (const auto &f: p.fields) n += f.text.rfind(prefix, 0) == 0;
    return n;
}

// Several packets through ONE parser, as a capture is read (the control request is remembered for its completion)
std::vector<packet::PacketInfo> parseAll(uint32_t linkType, const std::vector<Bytes> &frames,
                                         dissect::ParseMode mode = dissect::ParseMode::Full) {
    packet::PacketParser parser;
    std::vector<packet::PacketInfo> out;
    int number = 1;
    for (const auto &f: frames) {
        packet::PacketInfo pack(number++);
        pack.link_type = linkType;
        std::vector<char> raw(f.begin(), f.end());
        parser.parsePacket(pack, raw, mode);
        out.push_back(std::move(pack));
    }
    return out;
}

} // namespace

TEST(Usb, LinuxUsbControlSubmitCarriesTheSetupPacket) {
    const auto frame = usbmon(0x1122334455667788ULL, 'S', 2, 0x80, 3, 1, kGetDeviceDescriptor, {});
    ASSERT_EQ(frame.size(), 48u);
    const auto pkt = parseAll(189, {frame}).front();

    EXPECT_EQ(pkt.protocol, "USB");
    EXPECT_EQ(pkt.app_type, 2); // CONTROL
    // a submit goes from the host to the device, whatever the transfer direction
    EXPECT_EQ(pkt.source, "host");
    EXPECT_EQ(pkt.destination, "1.3");
    EXPECT_EQ(pkt.info, "URB Submit CONTROL IN (Dev 3, Ep 0) GET_DESCRIPTOR");
    const auto *setup = findNode(pkt.fields, "Setup Packet: GET_DESCRIPTOR");
    ASSERT_NE(setup, nullptr);
    EXPECT_EQ(setup->offset, 40u);
    EXPECT_EQ(setup->length, 8u);
    ASSERT_NE(findNode(pkt.fields, "wValue: 0x0100"), nullptr);
    ASSERT_NE(findNode(pkt.fields, "wLength: 18"), nullptr);
}

TEST(Usb, TheUrbIdKeepsAllSixtyFourBits) {
    const auto pkt = parseAll(189, {usbmon(0x1122334455667788ULL, 'S', 2, 0x80, 3, 1, kGetDeviceDescriptor, {})}).front();
    const auto *id = findNode(pkt.fields, "URB ID: ");
    ASSERT_NE(id, nullptr);
    EXPECT_EQ(id->text, "URB ID: 0x1122334455667788");
    EXPECT_EQ(findNode(pkt.fields, "Endpoint: 0x80 (IN)") != nullptr, true) << "no doubled 0x prefix";
}

TEST(Usb, DescriptorsAreDecodedForTheCompletionOfGetDescriptor) {
    const Bytes submit = usbmon(0xAB, 'S', 2, 0x80, 3, 1, kGetDeviceDescriptor, {});
    // a device descriptor is followed by a configuration descriptor in the same buffer: the 18 byte DEVICE descriptor must
    // be consumed exactly, or the second one is read misaligned
    const Bytes data = cat(kDeviceDescriptor, Bytes{9, 2, 25, 0, 1, 1, 0, 0xe0, 0});
    const Bytes complete = usbmon(0xAB, 'C', 2, 0x80, 3, 1, {}, data);
    const auto pkts = parseAll(189, {submit, complete});

    const auto &c = pkts[1];
    EXPECT_EQ(c.source, "1.3");
    EXPECT_EQ(c.destination, "host");
    EXPECT_EQ(c.info, "URB Complete CONTROL IN (Dev 3, Ep 0) GET_DESCRIPTOR [27 bytes]");
    ASSERT_EQ(countLayers(c, "USB Descriptor: "), 2);
    EXPECT_EQ(c.fields[2].text, "USB Descriptor: DEVICE");  // fields[0] = Frame, [1] = the URB header
    EXPECT_EQ(c.fields[2].offset, 48u);
    EXPECT_EQ(c.fields[2].length, 18u);
    EXPECT_EQ(c.fields[3].text, "USB Descriptor: CONFIGURATION");
    EXPECT_EQ(c.fields[3].offset, 66u);
    const auto *vid = findNode(c.fields, "idVendor: 0x1d6b");
    ASSERT_NE(vid, nullptr);
    EXPECT_EQ(vid->offset, 56u);
    ASSERT_NE(findNode(c.fields, "idProduct: 0x0002"), nullptr);
    ASSERT_NE(findNode(c.fields, "bcdDevice: 0x0510"), nullptr);
    ASSERT_NE(findNode(c.fields, "bcdUSB: 0x0200"), nullptr);
    ASSERT_NE(findNode(c.fields, "bMaxPacketSize0: 64"), nullptr);
    ASSERT_NE(findNode(c.fields, "wTotalLength: 25"), nullptr);
    framesweep::expectInside(c, complete.size(), "descriptors");
}

TEST(Usb, ConfigurationChainShowsInterfaceAndEndpoint) {
    const auto pkts = parseAll(189, {usbmon(1, 'S', 2, 0x80, 2, 1, kGetConfigDescriptor, {}),
                                     usbmon(1, 'C', 2, 0x80, 2, 1, {}, kConfigChain)});
    const auto &c = pkts[1];
    ASSERT_EQ(countLayers(c, "USB Descriptor: "), 3);
    ASSERT_NE(findNode(c.fields, "bInterfaceClass: 0x09"), nullptr);
    ASSERT_NE(findNode(c.fields, "bEndpointAddress: 0x81"), nullptr);
    ASSERT_NE(findNode(c.fields, "wMaxPacketSize: 4"), nullptr);
    ASSERT_NE(findNode(c.fields, "bInterval: 12"), nullptr);
}

TEST(Usb, PayloadsThatAreNotDescriptorsAreNotDecodedAsDescriptors) {
    // bulk data that happens to look like a device descriptor
    const auto bulk = parseAll(189, {usbmon(7, 'C', 3, 0x81, 4, 1, {}, kDeviceDescriptor)}).front();
    EXPECT_EQ(countLayers(bulk, "USB Descriptor: "), 0);
    // a control completion without a seen request
    const auto orphan = parseAll(189, {usbmon(8, 'C', 2, 0x80, 4, 1, {}, kDeviceDescriptor)}).front();
    EXPECT_EQ(countLayers(orphan, "USB Descriptor: "), 0);
    // a control completion of another request (GET_STATUS)
    const auto status = parseAll(189, {usbmon(9, 'S', 2, 0x80, 4, 1, setupPacket(0x80, 0, 0, 0, 2), {}),
                                       usbmon(9, 'C', 2, 0x80, 4, 1, {}, Bytes{18, 1})}).back();
    EXPECT_EQ(countLayers(status, "USB Descriptor: "), 0);
    EXPECT_EQ(status.info, "URB Complete CONTROL IN (Dev 4, Ep 0) GET_STATUS [2 bytes]");
    // a class request with bRequest 6 is not the standard GET_DESCRIPTOR
    const auto cls = parseAll(189, {usbmon(10, 'S', 2, 0x80, 4, 1, setupPacket(0xA0, 6, 0x0100, 0, 18), {}),
                                    usbmon(10, 'C', 2, 0x80, 4, 1, {}, kDeviceDescriptor)}).back();
    EXPECT_EQ(countLayers(cls, "USB Descriptor: "), 0);
}

TEST(Usb, DirectionComesFromTheEndpointAddressNotFromTheEventType) {
    auto info = [](char event, uint8_t endpoint) {
        return parseAll(189, {usbmon(5, event, 3, endpoint, 6, 2, {}, Bytes{1, 2, 3, 4})}).front();
    };
    const auto outSubmit = info('S', 0x02);
    EXPECT_NE(outSubmit.info.find("BULK OUT"), std::string::npos);
    EXPECT_EQ(outSubmit.source, "host");
    EXPECT_EQ(outSubmit.destination, "2.6");
    const auto outComplete = info('C', 0x02);
    EXPECT_NE(outComplete.info.find("BULK OUT"), std::string::npos);
    EXPECT_EQ(outComplete.source, "2.6");
    EXPECT_EQ(outComplete.destination, "host");
    const auto inSubmit = info('S', 0x81);
    EXPECT_NE(inSubmit.info.find("BULK IN"), std::string::npos);
    EXPECT_EQ(inSubmit.source, "host");
    const auto inComplete = info('C', 0x81);
    EXPECT_NE(inComplete.info.find("BULK IN"), std::string::npos);
    EXPECT_EQ(inComplete.source, "2.6");
    EXPECT_EQ(inComplete.destination, "host");
}

TEST(Usb, MmappedHeaderIsSixtyFourBytes) {
    const Bytes submit = usbmon(3, 'S', 2, 0x80, 3, 1, kGetDeviceDescriptor, {}, 0, true);
    const Bytes complete = usbmon(3, 'C', 2, 0x80, 3, 1, {}, kDeviceDescriptor, 0, true);
    ASSERT_EQ(submit.size(), 64u);
    const auto pkts = parseAll(220, {submit, complete});
    ASSERT_NE(findNode(pkts[0].fields, "USB Linux Mmapped Extension"), nullptr);
    const auto &c = pkts[1];
    ASSERT_EQ(countLayers(c, "USB Descriptor: "), 1);
    EXPECT_EQ(c.fields.back().offset, 64u) << "the data starts after the 16 byte extension";
    EXPECT_NE(parseAll(220, {Bytes(63, 0)}).front().info.find("[Malformed Packet"), std::string::npos);
    EXPECT_NE(parseAll(189, {Bytes(47, 0)}).front().info.find("[Malformed Packet"), std::string::npos);
}

namespace {

// USBPcap packet: 27 byte header (+ stage byte for control transfers); `info` bit 0 = completion
Bytes usbPcap(uint64_t irp, uint8_t info, uint16_t bus, uint16_t device, uint8_t endpoint, uint8_t xfer, const Bytes &payload,
              int stage = -1, uint32_t dataLen = 0xFFFFFFFF) {
    Bytes b;
    putLe(b, stage >= 0 ? 28 : 27, 2);
    putLe(b, irp, 8);
    putLe(b, 0, 4);          // USBD status
    putLe(b, 0x0009, 2);     // function
    b.push_back(info);
    putLe(b, bus, 2);
    putLe(b, device, 2);
    b.push_back(endpoint);
    b.push_back(xfer);
    putLe(b, dataLen == 0xFFFFFFFF ? payload.size() : dataLen, 4);
    if (stage >= 0) b.push_back(static_cast<uint8_t>(stage));
    return cat(b, payload);
}

} // namespace

TEST(Usb, UsbPcapDirectionIsTheEndpointDirectionAndInfoIsRequestOrCompletion) {
    // bulk IN endpoint 0x81: a request (info bit 0 clear) is sent by the host, the completion comes from the device
    const auto inReq = parseAll(249, {usbPcap(0x1234, 0, 1, 4, 0x81, 3, {})}).front();
    EXPECT_NE(inReq.info.find("USBPcap BULK IN Request"), std::string::npos) << inReq.info;
    EXPECT_EQ(inReq.source, "host");
    EXPECT_EQ(inReq.destination, "1.4");
    Bytes data;
    for (int i = 0; i < 64; ++i) data.push_back(static_cast<uint8_t>(i));
    const auto inDone = parseAll(249, {usbPcap(0x1234, 1, 1, 4, 0x81, 3, data)}).front();
    EXPECT_EQ(inDone.info, "USBPcap BULK IN Completion (Dev 4, Ep 1) [64 bytes]");
    EXPECT_EQ(inDone.app_type, 3);
    EXPECT_EQ(inDone.source, "1.4");
    EXPECT_EQ(inDone.destination, "host");
    // bulk OUT endpoint 0x02: the request carries the data to the device
    const auto outReq = parseAll(249, {usbPcap(0x55, 0, 1, 4, 0x02, 3, data)}).front();
    EXPECT_EQ(outReq.info, "USBPcap BULK OUT Request (Dev 4, Ep 2) [64 bytes]");
    EXPECT_EQ(outReq.source, "host");
    EXPECT_EQ(outReq.destination, "1.4");
    const auto irpPkt = parseAll(249, {usbPcap(0x1234567890ABCDEFULL, 0, 1, 4, 0x02, 3, {})}).front();
    const auto irp = findNode(irpPkt.fields, "IRP ID: ");
    ASSERT_NE(irp, nullptr);
    EXPECT_EQ(irp->text, "IRP ID: 0x1234567890abcdef");
}

TEST(Usb, UsbPcapControlGetDescriptor) {
    // setup stage request (stage 0) with the 8 byte setup packet, then the completion carrying the descriptor
    const auto pkts = parseAll(249, {usbPcap(0x77, 0, 1, 5, 0x80, 2, kGetDeviceDescriptor, 0),
                                     usbPcap(0x77, 1, 1, 5, 0x80, 2, kDeviceDescriptor, 1)});
    EXPECT_EQ(pkts[0].info, "USBPcap CONTROL IN Request (Dev 5, Ep 0) GET_DESCRIPTOR [8 bytes]");
    const auto *setup = findNode(pkts[0].fields, "Setup Packet: GET_DESCRIPTOR");
    ASSERT_NE(setup, nullptr);
    EXPECT_EQ(setup->offset, 28u);
    EXPECT_EQ(pkts[1].info, "USBPcap CONTROL IN Completion (Dev 5, Ep 0) GET_DESCRIPTOR [18 bytes]");
    ASSERT_EQ(countLayers(pkts[1], "USB Descriptor: "), 1);
    EXPECT_EQ(pkts[1].fields.back().offset, 28u);
    ASSERT_NE(findNode(pkts[1].fields, "idVendor: 0x1d6b"), nullptr);
    // bulk payloads are never descriptors
    EXPECT_EQ(countLayers(parseAll(249, {usbPcap(0x78, 1, 1, 5, 0x81, 3, kDeviceDescriptor)}).front(), "USB Descriptor: "), 0);
    // a header only packet is complete (27 bytes), a shorter one is truncated
    EXPECT_EQ(parseAll(249, {usbPcap(0x79, 0, 1, 5, 0x81, 3, {})}).front().info.find("[Malformed"), std::string::npos);
    EXPECT_NE(parseAll(249, {Bytes(26, 0)}).front().info.find("[Malformed Packet"), std::string::npos);
    // a header length below the fixed size is invalid
    Bytes bad = usbPcap(0x7a, 0, 1, 5, 0x81, 3, {});
    bad[0] = 10;
    EXPECT_NE(parseAll(249, {bad}).front().info.find("[Malformed Packet"), std::string::npos);
}

TEST(Usb, ReplayDecodesDescriptorsFromTheStoredRequest) {
    // the load pass stores the request; a later replay of the completion (frozen tables) reads it back
    packet::PacketParser parser;
    const Bytes submit = usbmon(0xAB, 'S', 2, 0x80, 3, 1, kGetDeviceDescriptor, {});
    const Bytes complete = usbmon(0xAB, 'C', 2, 0x80, 3, 1, {}, kDeviceDescriptor);
    packet::PacketInfo a(1), b(2);
    a.link_type = b.link_type = 189;
    std::vector<char> ra(submit.begin(), submit.end()), rb(complete.begin(), complete.end());
    parser.parsePacket(a, ra, dissect::ParseMode::Summary);
    parser.parsePacket(b, rb, dissect::ParseMode::Summary);
    parser.sessions().freeze();
    packet::PacketInfo replay(2);
    replay.link_type = 189;
    parser.parsePacket(replay, rb, dissect::ParseMode::Replay);
    EXPECT_EQ(replay.info, b.info);
    EXPECT_EQ(countLayers(replay, "USB Descriptor: "), 1);
}

TEST(Usb, TruncationAndMutationStayInsideTheFrame) {
    framesweep::sweep(usbmon(1, 'S', 2, 0x80, 3, 1, kGetDeviceDescriptor, {}), 31, 400, 189);
    framesweep::sweep(usbmon(1, 'C', 2, 0x80, 3, 1, {}, cat(kDeviceDescriptor, kConfigChain)), 32, 400, 189);
    framesweep::sweep(usbmon(1, 'C', 2, 0x80, 3, 1, {}, kDeviceDescriptor, 0, true), 33, 400, 220);
    framesweep::sweep(usbPcap(1, 1, 1, 2, 0x80, 2, kDeviceDescriptor, 1), 34, 400, 249);
    framesweep::sweep(usbPcap(1, 0, 1, 2, 0x80, 2, kGetDeviceDescriptor, 0), 35, 400, 249);
}

TEST(Usb, SweepWithAnEarlierRequestStillStaysInside) {
    // mutated completions of a stored GET_DESCRIPTOR request: descriptor parsing sees hostile bytes
    uint32_t seed = 99;
    auto next = [&seed]() { seed = seed * 1664525u + 1013904223u; return seed >> 8; };
    for (int round = 0; round < 300; ++round) {
        Bytes data = cat(kDeviceDescriptor, kConfigChain);
        for (int i = 0; i < 3; ++i) data[next() % data.size()] = static_cast<uint8_t>(next());
        data.resize(next() % (data.size() + 1));
        const Bytes complete = usbmon(2, 'C', 2, 0x80, 3, 1, {}, data);
        const auto pkts = parseAll(189, {usbmon(2, 'S', 2, 0x80, 3, 1, kGetConfigDescriptor, {}), complete});
        framesweep::expectInside(pkts[1], complete.size(), "mutated descriptors, round " + std::to_string(round));
    }
}

TEST(Usb, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"USB"});
}
