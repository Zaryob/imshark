#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects Bluetooth HCI H4 packets (LinkType 187: LINKTYPE_BLUETOOTH_HCI_H4).
/// 1st byte is indicator: 1 = Command, 2 = ACL data, 3 = SCO data, 4 = Event.
void dissectBluetoothHciH4(Context &ctx, const char *data, size_t length);

/// Dissects Bluetooth Linux Monitor packets (LinkType 254: LINKTYPE_BLUETOOTH_LINUX_MONITOR).
/// 4-byte pseudo header (libpcap): adapter ID (uint16) and opcode (uint16), both in network byte order; the HCI packet
/// follows without a type indicator (the opcode tells command/event/ACL/SCO/ISO).
void dissectBluetoothLinuxMonitor(Context &ctx, const char *data, size_t length);

/// Dissects IEEE 802.15.4 MAC frames without a frame check sequence (LinkType 230: IEEE802_15_4_NOFCS).
void dissectIeee802154(Context &ctx, const char *data, size_t length);

/// LinkType 195 (IEEE802_15_4_WITHFCS): the MAC frame ends with a 16-bit FCS.
void dissectIeee802154WithFcs(Context &ctx, const char *data, size_t length);

/// LinkType 215 (IEEE802_15_4_NONASK_PHY): PHY header (preamble, SFD, frame length) in front of the MAC frame + FCS.
void dissectIeee802154NonaskPhy(Context &ctx, const char *data, size_t length);

} // namespace dissect
