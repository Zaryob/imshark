#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects Bluetooth HCI H4 packets (LinkType 187: LINKTYPE_BLUETOOTH_HCI_H4).
/// 1st byte is indicator: 1 = Command, 2 = ACL data, 3 = SCO data, 4 = Event.
void dissectBluetoothHciH4(Context &ctx, const char *data, size_t length);

/// Dissects Bluetooth Linux Monitor packets (LinkType 254: LINKTYPE_BLUETOOTH_LINUX_MONITOR).
/// 6-byte header: adapter ID (uint16), opcode (uint16), payload length (uint16).
void dissectBluetoothLinuxMonitor(Context &ctx, const char *data, size_t length);

/// Dissects IEEE 802.15.4 wireless personal area network frames (LinkType 195/215).
void dissectIeee802154(Context &ctx, const char *data, size_t length);

} // namespace dissect
