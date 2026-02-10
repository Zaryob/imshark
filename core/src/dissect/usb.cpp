#include "usb.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

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

void dissectUsbDescriptors(Context &ctx, const uint8_t *descData, size_t descLen, size_t fileOffset) {
    if (!ctx.wantFields() || descLen < 2) return;

    ByteReader r(descData, descLen);
    while (r.remaining() >= 2) {
        size_t descOffset = fileOffset + r.pos();
        uint8_t bLength = r.u8();
        uint8_t bDescriptorType = r.u8();

        if (bLength < 2 || bLength > r.remaining() + 2) {
            break;
        }

        const char *name = usbStandardDescriptorName(bDescriptorType);
        std::string dName = name ? name : ("TYPE_0x" + hexString(bDescriptorType, 2));

        auto &dNode = ctx.addLayer("USB Descriptor: " + dName, descOffset, bLength);
        dNode.add("bLength: " + std::to_string(bLength));
        dNode.add("bDescriptorType: " + dName + " (0x" + hexString(bDescriptorType, 2) + ")");

        size_t bodyLen = bLength - 2;
        if (bDescriptorType == 1 && bodyLen >= 16) { // DEVICE Descriptor
            uint16_t bcdUSB = r.u16_le();
            uint8_t bDevClass = r.u8();
            uint8_t bDevSubClass = r.u8();
            uint8_t bDevProto = r.u8();
            uint8_t bMaxPacketSize0 = r.u8();
            uint16_t idVendor = r.u16_le();
            uint16_t idProduct = r.u16_le();
            uint16_t bcdDevice = r.u16_le();
            r.skip(bodyLen - 14);

            dNode.add("bcdUSB: 0x" + hexString(bcdUSB, 4));
            dNode.add("bDeviceClass: 0x" + hexString(bDevClass, 2));
            dNode.add("bDeviceSubClass: 0x" + hexString(bDevSubClass, 2));
            dNode.add("bDeviceProtocol: 0x" + hexString(bDevProto, 2));
            dNode.add("bMaxPacketSize0: " + std::to_string(bMaxPacketSize0));
            dNode.add("idVendor: 0x" + hexString(idVendor, 4));
            dNode.add("idProduct: 0x" + hexString(idProduct, 4));
            dNode.add("bcdDevice: 0x" + hexString(bcdDevice, 4));
        } else if (bDescriptorType == 2 && bodyLen >= 7) { // CONFIGURATION
            uint16_t wTotalLength = r.u16_le();
            uint8_t bNumInterfaces = r.u8();
            uint8_t bConfigVal = r.u8();
            r.skip(bodyLen - 4);

            dNode.add("wTotalLength: " + std::to_string(wTotalLength));
            dNode.add("bNumInterfaces: " + std::to_string(bNumInterfaces));
            dNode.add("bConfigurationValue: " + std::to_string(bConfigVal));
        } else if (bDescriptorType == 4 && bodyLen >= 7) { // INTERFACE
            uint8_t bInterfaceNumber = r.u8();
            uint8_t bAlternateSetting = r.u8();
            uint8_t bNumEndpoints = r.u8();
            uint8_t bInterfaceClass = r.u8();
            uint8_t bInterfaceSubClass = r.u8();
            uint8_t bInterfaceProtocol = r.u8();
            r.skip(bodyLen - 6);

            dNode.add("bInterfaceNumber: " + std::to_string(bInterfaceNumber));
            dNode.add("bAlternateSetting: " + std::to_string(bAlternateSetting));
            dNode.add("bNumEndpoints: " + std::to_string(bNumEndpoints));
            dNode.add("bInterfaceClass: 0x" + hexString(bInterfaceClass, 2));
            dNode.add("bInterfaceSubClass: 0x" + hexString(bInterfaceSubClass, 2));
            dNode.add("bInterfaceProtocol: 0x" + hexString(bInterfaceProtocol, 2));
        } else if (bDescriptorType == 5 && bodyLen >= 5) { // ENDPOINT
            uint8_t bEndpointAddress = r.u8();
            uint8_t bmAttributes = r.u8();
            uint16_t wMaxPacketSize = r.u16_le();
            uint8_t bInterval = r.u8();
            r.skip(bodyLen - 5);

            dNode.add("bEndpointAddress: 0x" + hexString(bEndpointAddress, 2));
            dNode.add("bmAttributes: 0x" + hexString(bmAttributes, 2));
            dNode.add("wMaxPacketSize: " + std::to_string(wMaxPacketSize));
            dNode.add("bInterval: " + std::to_string(bInterval));
        } else {
            r.skip(bodyLen);
        }
    }
}

} // namespace

void dissectUsbLinux(Context &ctx, const char *data, size_t length) {
    if (!data || length < 48) {
        ctx.markMalformed("Truncated Linux USB header");
        ctx.pack.protocol = "USB";
        ctx.pack.info = "USB [Truncated Header]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint64_t urbId = r.u64_le();
    uint8_t eventType = r.u8();
    uint8_t transferType = r.u8();
    uint8_t endpoint = r.u8();
    uint8_t device = r.u8();
    uint16_t busId = r.u16_le();
    uint8_t setupFlag = r.u8();
    uint8_t dataFlag = r.u8();
    int64_t tsSec = r.i64_le();
    int32_t tsUsec = r.i32_le();
    (void)tsSec; (void)tsUsec;
    int32_t status = r.i32_le();
    uint32_t urbLen = r.u32_le();
    uint32_t dataLen = r.u32_le();

    ctx.pack.protocol = "USB";
    ctx.pack.app_type = transferType;

    bool isTx = (endpoint & 0x80) == 0; // OUT is host to device
    std::string direction = isTx ? "OUT" : "IN";
    std::string xferStr = usbTransferTypeName(transferType);
    std::string eventStr = usbEventTypeName(eventType);

    char srcBuf[32], dstBuf[32];
    if (isTx) {
        std::snprintf(srcBuf, sizeof(srcBuf), "host");
        std::snprintf(dstBuf, sizeof(dstBuf), "%u.%u", busId, device);
    } else {
        std::snprintf(srcBuf, sizeof(srcBuf), "%u.%u", busId, device);
        std::snprintf(dstBuf, sizeof(dstBuf), "host");
    }
    ctx.pack.source = srcBuf;
    ctx.pack.destination = dstBuf;

    std::string summary = "URB " + eventStr + " " + xferStr + " " + direction + " (Dev " + std::to_string(device) + ", Ep " + std::to_string(endpoint & 0x7F) + ")";
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
        root.add("URB ID: 0x" + hexString(urbId, 16));
        root.add("Event Type: " + eventStr + " ('" + std::string(1, static_cast<char>(eventType)) + "')");
        root.add("Transfer Type: " + xferStr + " (" + std::to_string(transferType) + ")");
        root.add("Endpoint: 0x" + hexString(endpoint, 2) + " (" + direction + ")");
        root.add("Device Address: " + std::to_string(device));
        root.add("Bus ID: " + std::to_string(busId));
        root.add("Status: " + std::to_string(status));
        root.add("URB Length: " + std::to_string(urbLen));
        root.add("Data Length: " + std::to_string(dataLen));

        // If control setup packet present (setupFlag == 0, 8 bytes at offset 40)
        if (setupFlag == 0 && length >= 48) {
            ByteReader sr(bytes + 40, 8);
            uint8_t bmReqType = sr.u8();
            uint8_t bReq = sr.u8();
            uint16_t wValue = sr.u16_le();
            uint16_t wIndex = sr.u16_le();
            uint16_t wLength = sr.u16_le();

            const char *reqName = usbStandardRequestName(bReq);
            std::string reqStr = reqName ? reqName : ("REQ_0x" + hexString(bReq, 2));

            auto &sNode = root.add("Setup Packet: " + reqStr, o + 40, 8);
            sNode.add("bmRequestType: 0x" + hexString(bmReqType, 2));
            sNode.add("bRequest: " + reqStr + " (" + std::to_string(bReq) + ")");
            sNode.add("wValue: 0x" + hexString(wValue, 4));
            sNode.add("wIndex: 0x" + hexString(wIndex, 4));
            sNode.add("wLength: " + std::to_string(wLength));
        }

        // Dissect payload descriptors if complete GET_DESCRIPTOR response
        if (length > 48 && dataFlag == 0) {
            dissectUsbDescriptors(ctx, bytes + 48, length - 48, o + 48);
        }
    }
}

void dissectUsbLinuxMmapped(Context &ctx, const char *data, size_t length) {
    if (!data || length < 64) {
        dissectUsbLinux(ctx, data, length);
        return;
    }

    // First 48 bytes are identical to usbmon standard header
    dissectUsbLinux(ctx, data, length);

    if (ctx.wantFields() && length >= 64) {
        const auto *bytes = reinterpret_cast<const uint8_t *>(data);
        ByteReader r(bytes + 48, 16);
        int32_t interval = r.i32_le();
        int32_t startFrame = r.i32_le();
        uint32_t xferFlags = r.u32_le();
        uint32_t numDesc = r.u32_le();

        const size_t o = ctx.offsetOf(data) + 48;
        auto &mNode = ctx.addLayer("USB Linux Mmapped Extension", o, 16);
        mNode.add("Interval: " + std::to_string(interval));
        mNode.add("Start Frame: " + std::to_string(startFrame));
        mNode.add("Transfer Flags: 0x" + hexString(xferFlags, 8));
        mNode.add("Number of Isochronous Descriptors: " + std::to_string(numDesc));
    }
}

void dissectUsbPcap(Context &ctx, const char *data, size_t length) {
    if (!data || length < 28) {
        ctx.markMalformed("Truncated USBPcap header");
        ctx.pack.protocol = "USB";
        ctx.pack.info = "USBPcap [Truncated Header]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint16_t headerLen = r.u16_le();
    uint64_t irpId = r.u64_le();
    uint32_t usbdStatus = r.u32_le();
    uint16_t function = r.u16_le();
    uint8_t info = r.u8();
    uint16_t busId = r.u16_le();
    uint16_t device = r.u16_le();
    uint8_t endpoint = r.u8();
    uint8_t transferType = r.u8();
    uint32_t dataLen = r.u32_le();

    ctx.pack.protocol = "USB";
    ctx.pack.app_type = transferType;

    bool isTx = (info & 0x01) == 0; // 0 = PDO -> FDO (OUT), 1 = FDO -> PDO (IN)
    std::string direction = isTx ? "OUT" : "IN";
    std::string xferStr = usbTransferTypeName(transferType);

    char srcBuf[32], dstBuf[32];
    if (isTx) {
        std::snprintf(srcBuf, sizeof(srcBuf), "host");
        std::snprintf(dstBuf, sizeof(dstBuf), "%u.%u", busId, device);
    } else {
        std::snprintf(srcBuf, sizeof(srcBuf), "%u.%u", busId, device);
        std::snprintf(dstBuf, sizeof(dstBuf), "host");
    }
    ctx.pack.source = srcBuf;
    ctx.pack.destination = dstBuf;

    std::string summary = "USBPcap " + xferStr + " " + direction + " (Dev " + std::to_string(device) + ", Ep " + std::to_string(endpoint & 0x7F) + ")";
    if (usbdStatus != 0) {
        summary += " Status: 0x" + hexString(usbdStatus, 8);
    }
    if (dataLen > 0) {
        summary += " [" + std::to_string(dataLen) + " bytes]";
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("USBPcap (" + xferStr + " " + direction + ")", o, headerLen <= length ? headerLen : length);
        root.add("Header Length: " + std::to_string(headerLen));
        root.add("IRP ID: 0x" + hexString(irpId, 16));
        root.add("USBD Status: 0x" + hexString(usbdStatus, 8));
        root.add("Function: 0x" + hexString(function, 4));
        root.add("Bus ID: " + std::to_string(busId));
        root.add("Device Address: " + std::to_string(device));
        root.add("Endpoint: 0x" + hexString(endpoint, 2) + " (" + direction + ")");
        root.add("Transfer Type: " + xferStr + " (" + std::to_string(transferType) + ")");
        root.add("Data Length: " + std::to_string(dataLen));

        if (headerLen <= length && length > headerLen) {
            dissectUsbDescriptors(ctx, bytes + headerLen, length - headerLen, o + headerLen);
        }
    }
}

} // namespace dissect
