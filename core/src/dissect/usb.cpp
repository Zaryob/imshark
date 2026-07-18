#include "usb.h"
#include "reader.h"
#include "util.h"
#include <algorithm>
#include <cstdio>
#include <string>

namespace dissect {

namespace {

uint16_t le16(const uint8_t *p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }

const char *usbTransferTypeName(uint8_t xferType) {
    switch (xferType) {
        case 0: return "ISOCHRONOUS";
        case 1: return "INTERRUPT";
        case 2: return "CONTROL";
        case 3: return "BULK";
        default: return "UNKNOWN";
    }
}

const char *usbEventTypeName(uint8_t eventType) {
    switch (eventType) {
        case 'S': return "Submit";
        case 'C': return "Complete";
        case 'E': return "Error";
        default: return "Event";
    }
}

const char *usbStandardDescriptorName(uint8_t descType) {
    switch (descType) {
        case 1: return "DEVICE";
        case 2: return "CONFIGURATION";
        case 3: return "STRING";
        case 4: return "INTERFACE";
        case 5: return "ENDPOINT";
        case 6: return "DEVICE_QUALIFIER";
        case 7: return "OTHER_SPEED_CONFIGURATION";
        case 8: return "INTERFACE_POWER";
        case 0x21: return "HID";
        case 0x22: return "HID_REPORT";
        case 0x23: return "PHYSICAL";
        case 0x29: return "HUB";
        default: return nullptr;
    }
}

const char *usbStandardRequestName(uint8_t req) {
    switch (req) {
        case 0: return "GET_STATUS";
        case 1: return "CLEAR_FEATURE";
        case 3: return "SET_FEATURE";
        case 5: return "SET_ADDRESS";
        case 6: return "GET_DESCRIPTOR";
        case 7: return "SET_DESCRIPTOR";
        case 8: return "GET_CONFIGURATION";
        case 9: return "SET_CONFIGURATION";
        case 10: return "GET_INTERFACE";
        case 11: return "SET_INTERFACE";
        case 12: return "SYNCH_FRAME";
        default: return nullptr;
    }
}

std::string hex64(uint64_t v) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%016llx", static_cast<unsigned long long>(v));
    return buf;
}

// Standard descriptors in `descLen` bytes at `descData` (absolute offset `base`). Returns after the first one that does
// not fit.
void dissectUsbDescriptors(Context &ctx, const uint8_t *descData, size_t descLen, size_t base) {
    if (!ctx.wantFields() || descLen < 2) return;

    size_t pos = 0;
    while (descLen - pos >= 2) {
        const uint8_t *d = descData + pos;
        const size_t at = base + pos;
        const uint8_t bLength = d[0];
        const uint8_t bDescriptorType = d[1];
        if (bLength < 2 || bLength > descLen - pos) break;

        const char *name = usbStandardDescriptorName(bDescriptorType);
        const std::string dName = name ? name : ("TYPE_" + hexString(bDescriptorType, 2));

        auto &dNode = ctx.addLayer("USB Descriptor: " + dName, at, bLength);
        dNode.add("bLength: " + std::to_string(bLength), at, 1);
        dNode.add("bDescriptorType: " + dName + " (" + hexString(bDescriptorType, 2) + ")", at + 1, 1);

        const size_t bodyLen = bLength - 2u;
        if (bDescriptorType == 1 && bodyLen >= 16) { // DEVICE: the remaining 4 bytes are iManufacturer .. bNumConfigurations
            dNode.add("bcdUSB: " + hexString(le16(d + 2), 4), at + 2, 2);
            dNode.add("bDeviceClass: " + hexString(d[4], 2), at + 4, 1);
            dNode.add("bDeviceSubClass: " + hexString(d[5], 2), at + 5, 1);
            dNode.add("bDeviceProtocol: " + hexString(d[6], 2), at + 6, 1);
            dNode.add("bMaxPacketSize0: " + std::to_string(d[7]), at + 7, 1);
            dNode.add("idVendor: " + hexString(le16(d + 8), 4), at + 8, 2);
            dNode.add("idProduct: " + hexString(le16(d + 10), 4), at + 10, 2);
            dNode.add("bcdDevice: " + hexString(le16(d + 12), 4), at + 12, 2);
        } else if (bDescriptorType == 2 && bodyLen >= 7) { // CONFIGURATION
            dNode.add("wTotalLength: " + std::to_string(le16(d + 2)), at + 2, 2);
            dNode.add("bNumInterfaces: " + std::to_string(d[4]), at + 4, 1);
            dNode.add("bConfigurationValue: " + std::to_string(d[5]), at + 5, 1);
        } else if (bDescriptorType == 4 && bodyLen >= 7) { // INTERFACE
            dNode.add("bInterfaceNumber: " + std::to_string(d[2]), at + 2, 1);
            dNode.add("bAlternateSetting: " + std::to_string(d[3]), at + 3, 1);
            dNode.add("bNumEndpoints: " + std::to_string(d[4]), at + 4, 1);
            dNode.add("bInterfaceClass: " + hexString(d[5], 2), at + 5, 1);
            dNode.add("bInterfaceSubClass: " + hexString(d[6], 2), at + 6, 1);
            dNode.add("bInterfaceProtocol: " + hexString(d[7], 2), at + 7, 1);
        } else if (bDescriptorType == 5 && bodyLen >= 5) { // ENDPOINT
            dNode.add("bEndpointAddress: " + hexString(d[2], 2), at + 2, 1);
            dNode.add("bmAttributes: " + hexString(d[3], 2), at + 3, 1);
            dNode.add("wMaxPacketSize: " + std::to_string(le16(d + 4)), at + 4, 2);
            dNode.add("bInterval: " + std::to_string(d[6]), at + 6, 1);
        }
        pos += bLength;
    }
}

// The endpoint address of the transfer (bit 7 = IN) goes into app_flags with bit 8 set, so that "no endpoint" (packets without a
// readable header) differs from endpoint 0x00: the statistics and the usb.endpoint filter field read it.
constexpr uint16_t kUsbEndpointKnown = 0x100;

const char *usbDirection(uint8_t endpoint) { return (endpoint & 0x80) ? "IN" : "OUT"; }

std::string usbAddress(unsigned bus, unsigned device) { return std::to_string(bus) + "." + std::to_string(device); }

// A request travels from the host to the device, a completion (or error) back: that decides source and destination.
// The transfer direction (IN/OUT) is a property of the endpoint and is shown separately.
void setUsbEndpoints(Context &ctx, bool request, unsigned bus, unsigned device) {
    const std::string dev = usbAddress(bus, device);
    ctx.pack.source = request ? "host" : dev;
    ctx.pack.destination = request ? dev : "host";
}

void addSetupNode(Context &ctx, packet::Field &parent, const uint8_t *s, size_t at) {
    (void)ctx;
    const uint8_t bmReqType = s[0], bReq = s[1];
    const char *reqName = usbStandardRequestName(bReq);
    const std::string reqStr = reqName ? reqName : ("REQ_" + hexString(bReq, 2));
    auto &sNode = parent.add("Setup Packet: " + reqStr, at, 8);
    sNode.add("bmRequestType: " + hexString(bmReqType, 2), at, 1);
    sNode.add("bRequest: " + reqStr + " (" + std::to_string(bReq) + ")", at + 1, 1);
    sNode.add("wValue: " + hexString(le16(s + 2), 4), at + 2, 2);
    sNode.add("wIndex: " + hexString(le16(s + 4), 4), at + 4, 2);
    sNode.add("wLength: " + std::to_string(le16(s + 6)), at + 6, 2);
}

UsbControlRequest requestFrom(const uint8_t *s) {
    UsbControlRequest r;
    r.bmRequestType = s[0];
    r.bRequest = s[1];
    r.wValue = le16(s + 2);
    r.wIndex = le16(s + 4);
    r.wLength = le16(s + 6);
    return r;
}

// Linux usbmon binary header (Documentation/usb/usbmon.rst, struct mon_bin_hdr): 48 bytes, followed (link type 220) by
// the 16 byte mmapped extension, then the captured data.
void dissectUsbmon(Context &ctx, const char *data, size_t length, size_t headerLen) {
    if (!data || length < headerLen) {
        ctx.pack.protocol = "USB";
        ctx.pack.info = "USB [Truncated Header]";
        ctx.markMalformed("Truncated Linux USB header");
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    const uint64_t urbId = r.u64_le();
    const uint8_t eventType = r.u8();
    const uint8_t transferType = r.u8();
    const uint8_t endpoint = r.u8();
    const uint8_t device = r.u8();
    const uint16_t busId = r.u16_le();
    const uint8_t setupFlag = r.u8();
    const uint8_t dataFlag = r.u8();
    r.skip(12); // ts_sec, ts_usec
    const int32_t status = r.i32_le();
    const uint32_t urbLen = r.u32_le();
    const uint32_t dataLen = r.u32_le();

    ctx.pack.protocol = "USB";
    ctx.pack.app_type = transferType;
    ctx.pack.app_flags = static_cast<uint16_t>(kUsbEndpointKnown | endpoint);

    const bool request = eventType == 'S';
    const std::string direction = usbDirection(endpoint);
    const std::string xferStr = usbTransferTypeName(transferType);
    const std::string eventStr = usbEventTypeName(eventType);
    setUsbEndpoints(ctx, request, busId, device);

    // Control transfers: remember the request of a submit, find it again for the completion (load pass and replay alike)
    const bool control = transferType == 2;
    const bool haveSetup = control && setupFlag == 0;
    UsbControlRequest setup;
    if (haveSetup) setup = requestFrom(bytes + 40);
    const UsbControlRequest *answered = nullptr;
    if (control && ctx.sessions) {
        const uint32_t number = static_cast<uint32_t>(ctx.pack.number);
        if (request && haveSetup) {
            ctx.sessions->addUsbRequest(urbId, setup);
        } else if (!request) {
            ctx.sessions->completeUsbRequest(urbId, number);
            answered = ctx.sessions->usbRequestOf(number);
        }
    }
    const UsbControlRequest *shown = haveSetup ? &setup : answered;

    std::string summary = "URB " + eventStr + " " + xferStr + " " + direction + " (Dev " + std::to_string(device) + ", Ep " + std::to_string(endpoint & 0x7F) + ")";
    if (shown) {
        const char *reqName = usbStandardRequestName(shown->bRequest);
        if (reqName && (shown->bmRequestType & 0x60) == 0) summary += std::string(" ") + reqName;
    }
    if (status != 0) {
        summary += " Status: " + std::to_string(status);
        ctx.pack.app_code = static_cast<uint16_t>(status & 0xFFFF);
    }
    if (dataLen > 0) {
        summary += " [" + std::to_string(dataLen) + " bytes]";
    }
    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("USB URB (" + xferStr + " " + eventStr + ")", o, 48);
        root.add("URB ID: " + hex64(urbId), o, 8);
        root.add("Event Type: " + eventStr + " ('" + std::string(1, (eventType >= 32 && eventType < 127) ? static_cast<char>(eventType) : '?') + "')", o + 8, 1);
        root.add("Transfer Type: " + xferStr + " (" + std::to_string(transferType) + ")", o + 9, 1);
        root.add("Endpoint: " + hexString(endpoint, 2) + " (" + direction + ")", o + 10, 1);
        root.add("Device Address: " + std::to_string(device), o + 11, 1);
        root.add("Bus ID: " + std::to_string(busId), o + 12, 2);
        root.add("Status: " + std::to_string(status), o + 28, 4);
        root.add("URB Length: " + std::to_string(urbLen), o + 32, 4);
        root.add("Data Length: " + std::to_string(dataLen), o + 36, 4);

        if (haveSetup) addSetupNode(ctx, root, bytes + 40, o + 40);

        if (headerLen >= 64) {
            ByteReader m(bytes + 48, 16);
            const int32_t interval = m.i32_le();
            const int32_t startFrame = m.i32_le();
            const uint32_t xferFlags = m.u32_le();
            const uint32_t numDesc = m.u32_le();
            auto &mNode = ctx.addLayer("USB Linux Mmapped Extension", o + 48, 16);
            mNode.add("Interval: " + std::to_string(interval), o + 48, 4);
            mNode.add("Start Frame: " + std::to_string(startFrame), o + 52, 4);
            mNode.add("Transfer Flags: " + hexString(xferFlags, 8), o + 56, 4);
            mNode.add("Number of Isochronous Descriptors: " + std::to_string(numDesc), o + 60, 4);
        }

        // Descriptors only in the data of the completion of a GET_DESCRIPTOR request (not in any payload)
        if (!request && answered && answered->isGetDescriptor() && dataFlag == 0 && length > headerLen) {
            const size_t present = std::min<size_t>(length - headerLen, dataLen);
            dissectUsbDescriptors(ctx, bytes + headerLen, present, o + headerLen);
        }
    }
}

// USBPcap (https://desowin.org/usbpcap/captureformat.html): 27 byte packet header, control transfers add a stage byte.
// info bit 0 is set for a completion (PDO to FDO), clear for a request (FDO to PDO).
void dissectUsbPcapPacket(Context &ctx, const char *data, size_t length) {
    if (!data || length < 27) {
        ctx.pack.protocol = "USB";
        ctx.markMalformed("Truncated USBPcap header");
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    const uint16_t headerLen = r.u16_le();
    const uint64_t irpId = r.u64_le();
    const uint32_t usbdStatus = r.u32_le();
    const uint16_t function = r.u16_le();
    const uint8_t info = r.u8();
    const uint16_t busId = r.u16_le();
    const uint16_t device = r.u16_le();
    const uint8_t endpoint = r.u8();
    const uint8_t transferType = r.u8();
    const uint32_t dataLen = r.u32_le();

    ctx.pack.protocol = "USB";
    ctx.pack.app_type = transferType;
    ctx.pack.app_flags = static_cast<uint16_t>(kUsbEndpointKnown | endpoint);

    const bool completion = (info & 0x01) != 0;
    const std::string direction = usbDirection(endpoint);
    const std::string xferStr = usbTransferTypeName(transferType);
    setUsbEndpoints(ctx, !completion, busId, device);

    const bool badHeader = headerLen < 27 || headerLen > length;
    const size_t hdr = badHeader ? 27 : headerLen;
    const bool control = transferType == 2 && hdr >= 28;
    const uint8_t stage = control ? bytes[27] : 0;
    const size_t present = length - hdr;

    // Control transfers: a setup stage request carries the 8 byte setup packet; the completion with the same IRP id answers it
    UsbControlRequest setup;
    bool haveSetup = false;
    const UsbControlRequest *answered = nullptr;
    if (control && !badHeader) {
        haveSetup = !completion && stage == 0 && present >= 8;
        if (haveSetup) setup = requestFrom(bytes + hdr);
        if (ctx.sessions) {
            const uint32_t number = static_cast<uint32_t>(ctx.pack.number);
            if (haveSetup) ctx.sessions->addUsbRequest(irpId, setup);
            else if (completion) {
                ctx.sessions->completeUsbRequest(irpId, number);
                answered = ctx.sessions->usbRequestOf(number);
            }
        }
    }
    const UsbControlRequest *shown = haveSetup ? &setup : answered;

    std::string summary = "USBPcap " + xferStr + " " + direction + (completion ? " Completion" : " Request") +
                          " (Dev " + std::to_string(device) + ", Ep " + std::to_string(endpoint & 0x7F) + ")";
    if (shown) {
        const char *reqName = usbStandardRequestName(shown->bRequest);
        if (reqName && (shown->bmRequestType & 0x60) == 0) summary += std::string(" ") + reqName;
    }
    if (usbdStatus != 0) {
        summary += " Status: " + hexString(usbdStatus, 8);
    }
    if (dataLen > 0) {
        summary += " [" + std::to_string(dataLen) + " bytes]";
    }
    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("USBPcap (" + xferStr + " " + direction + ")", o, hdr);
        root.add("Header Length: " + std::to_string(headerLen), o, 2);
        root.add("IRP ID: " + hex64(irpId), o + 2, 8);
        root.add("USBD Status: " + hexString(usbdStatus, 8), o + 10, 4);
        root.add("Function: " + hexString(function, 4), o + 14, 2);
        root.add(std::string("IRP Information: ") + (completion ? "PDO to FDO (completion)" : "FDO to PDO (request)") +
                     " (" + hexString(info, 2) + ")", o + 16, 1);
        root.add("Bus ID: " + std::to_string(busId), o + 17, 2);
        root.add("Device Address: " + std::to_string(device), o + 19, 2);
        root.add("Endpoint: " + hexString(endpoint, 2) + " (" + direction + ")", o + 21, 1);
        root.add("Transfer Type: " + xferStr + " (" + std::to_string(transferType) + ")", o + 22, 1);
        root.add("Data Length: " + std::to_string(dataLen), o + 23, 4);
        if (control) root.add("Control Stage: " + std::to_string(stage), o + 27, 1);
        if (haveSetup) addSetupNode(ctx, root, bytes + hdr, o + hdr);

        if (!badHeader && completion && answered && answered->isGetDescriptor() && present > 0) {
            dissectUsbDescriptors(ctx, bytes + hdr, std::min<size_t>(present, dataLen), o + hdr);
        }
    }
    if (badHeader) ctx.markMalformed(headerLen < 27 ? "USBPcap header length is too small" : "Truncated USBPcap header");
}

} // namespace

void dissectUsbLinux(Context &ctx, const char *data, size_t length) { dissectUsbmon(ctx, data, length, 48); }

void dissectUsbLinuxMmapped(Context &ctx, const char *data, size_t length) { dissectUsbmon(ctx, data, length, 64); }

void dissectUsbPcap(Context &ctx, const char *data, size_t length) { dissectUsbPcapPacket(ctx, data, length); }

} // namespace dissect
