#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects Linux USB capture (LinkType 189: LINKTYPE_USB_LINUX).
/// Header length: 48 bytes (standard usbmon header).
void dissectUsbLinux(Context &ctx, const char *data, size_t length);

/// Dissects Linux USB mmapped capture (LinkType 220: LINKTYPE_USB_LINUX_MMAPPED).
/// Header length: 64 bytes (extended usbmon header with ndesc/iso).
void dissectUsbLinuxMmapped(Context &ctx, const char *data, size_t length);

/// Dissects USBPcap capture (LinkType 249: LINKTYPE_USBPCAP).
/// Header length: variable (headerLen field in header, min 28 bytes).
void dissectUsbPcap(Context &ctx, const char *data, size_t length);

} // namespace dissect
