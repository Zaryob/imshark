#pragma once

#include "context.h"
#include <cstdint>
#include <string>

namespace dissect {

// app_flags of a DCERPC packet (PacketInfo summary facts)
constexpr uint16_t kDceFlagOpnum = 0x01;            // a Request: app_code is the opnum
constexpr uint16_t kDceFlagConnectionless = 0x02;   // a version 4 (datagram) PDU
constexpr uint16_t kDceAuthShift = 2;               // bits 2..4: authentication level of the PDU's verifier (0 = none)
constexpr uint16_t kDceAuthMask = 0x1C;
constexpr uint16_t kDceFlagSealed = 0x20;           // the stub data is sealed (packet privacy) or its framing is not known: not interpreted
constexpr uint16_t kDceFlagReassembled = 0x40;      // this PDU completes a call that was split into fragments
constexpr uint16_t kDceFlagFragment = 0x80;         // part of a call split over several PDUs
// app_flags of an SMB2 packet whose first command carried a PDU in a named pipe (bits 8..15 are free there; app_code is the opnum,
// app_text the interface UUID; the call id is not stored, SMB2 responses keep their NT status in app_stream)
constexpr uint16_t kDcePipePdu = 0x100;             // the first command carried a DCE/RPC PDU
constexpr uint16_t kDcePipeOpnum = 0x200;           // ... a Request
constexpr uint16_t kDcePipeTypeShift = 10;          // bits 10..14: PDU type
constexpr uint16_t kDcePipeTypeMask = 0x7C00;

/// Dissects connection-oriented DCE/RPC (version 5) PDUs: over TCP (port 135 and the ports the endpoint mapper announced), and,
/// through dissectDceRpcPipe(), inside SMB2 named pipes.
void dissectDceRpc(Context &ctx, const char *data, size_t length);

/// Frames connection-oriented DCE/RPC PDUs from a TCP stream.
StreamFrame frameDceRpc(const char *data, size_t length);

/// Dissects a connectionless (version 4) PDU carried by a UDP datagram (port 135, the ports the endpoint mapper announced, Decode As).
/// Anything else leaves the packet to UDP.
void dissectDceRpcDatagram(Context &ctx, const char *data, size_t length);

/// What the SMB2 dissector learns from a PDU found in a named pipe transfer.
struct DceRpcPipeResult {
    bool decoded = false;        // the bytes were a PDU of this protocol (the SMB2 packet then carries it)
    std::string info;            // "Bind (CallID: 2), Bind: SRVSVC (Server Service)"
    uint8_t type = 0;
    bool request = false;
    uint16_t opnum = 0;
    std::string interfaceUuid;
    const char *malformed = nullptr;   // why the complete PDU does not decode (the caller marks its packet after naming it)
};

/// Decodes the bytes of one SMB2 Write / Read / IOCTL FSCTL_PIPE_TRANSCEIVE transfer on a named pipe: a PDU, added as a layer of the
/// packet (the packet's protocol stays SMB2). `pipeStream` identifies the pipe handle (connection + FileId), `seq` and `index` the
/// message and command inside the packet (the keys of the session note).
DceRpcPipeResult dissectDceRpcPipe(Context &ctx, const char *data, size_t length, const std::string &pipeStream, int64_t seq, uint8_t index);

} // namespace dissect
