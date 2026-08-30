#pragma once

#include "context.h"
#include <cstdint>
#include <string>

namespace dissect {

/// Dissects Kerberos (v5) protocol packets (RFC 4120).
/// Supported over UDP (port 88) and TCP (port 88 with 4-byte big-endian length prefix).
void dissectKerberos(Context &ctx, const char *data, size_t length);

/// What decodeKerberosMessage found: the facts the summary line, the packet columns and callers such as SPNEGO need.
struct KerberosSummary {
    bool tagOk = false;     // an APPLICATION tag with a readable length starts the bytes
    bool cut = false;       // the message is longer than the bytes given
    bool bodyOk = false;    // complete and the body is a SEQUENCE
    uint32_t appTag = 0;    // 10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 14 AP-REQ, 15 AP-REP, 20 KRB-SAFE, 21 KRB-PRIV, 22 KRB-CRED, 30 KRB-ERROR
    int64_t msgType = 0;
    int64_t errorCode = -1; // KRB-ERROR only
    size_t length = 0;      // bytes of the message inside the given bytes
    std::string typeName, cname, sname, crealm, realm;
    std::string info;       // "AP-REQ sname=cifs/files.corp.com realm=CORP.COM"
};

/// Decodes ONE Kerberos message (no TCP record mark; `msg` lies inside the frame of `ctx`). When `root` is given (and the
/// mode wants fields) its text, length and children are filled: EncryptedData is labelled "(encrypted)" and never decoded;
/// the AP-REQ inside PA-TGS-REQ is decoded too. `depth` bounds that nesting. The SPNEGO decoder reuses this.
KerberosSummary decodeKerberosMessage(Context &ctx, const uint8_t *msg, size_t length, packet::Field *root, int depth = 0);

/// Frames Kerberos PDUs from a TCP stream.
StreamFrame frameKerberos(const char *data, size_t length);

} // namespace dissect
