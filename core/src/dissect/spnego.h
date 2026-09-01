#pragma once

// GSS-API / SPNEGO security blobs (RFC 4178, RFC 2743 3.1, RFC 4121): the token that SMB2 Session Setup, LDAP SASL binds
// (GSS-SPNEGO, GSSAPI), DCE/RPC and HTTP Negotiate carry. The decoder recognises
//   - the GSS-API InitialContextToken ([APPLICATION 0] mech OID + token) of SPNEGO and of Kerberos 5,
//   - a bare NegTokenInit ([0]) or NegTokenResp ([1]),
//   - a bare Kerberos AP-REQ / AP-REP / KRB-ERROR,
//   - NTLMSSP messages (located, not decoded: the owner of the protocol decodes them) and Kerberos Wrap/MIC tokens (labelled),
// and decodes the Kerberos message inside it through decodeKerberosMessage() (kerberos.h).
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "context.h"
#include "kerberos.h"

namespace dissect {

struct SecurityBlob {
    bool ok = false;                        // something was recognised
    std::string kind;                       // "SPNEGO NegTokenInit", "GSS-API Kerberos 5 AP-REQ", "NTLMSSP", ...
    std::vector<std::string> offeredMechs;  // NegTokenInit mechTypes (OIDs, in the order offered)
    std::string mech;                       // thisMech of a GSS-API token / supportedMech of a NegTokenResp (OID), else empty
    std::string negState;                   // NegTokenResp: accept-completed, accept-incomplete, reject, request-mic
    bool hasKerberos = false;               // a Kerberos message was found (also inside the mechToken)
    KerberosSummary kerberos;               //   its facts (typeName, sname, realm, ...)
    bool hasNtlmssp = false;                // an NTLMSSP message was found: the bytes, inside `blob`
    const uint8_t *ntlmssp = nullptr;
    size_t ntlmsspLength = 0;
    const uint8_t *mechToken = nullptr;     // NegTokenInit mechToken / NegTokenResp responseToken (inside `blob`)
    size_t mechTokenLength = 0;
    std::string summary;                    // one line for an Info column: "SPNEGO NegTokenInit [Kerberos 5, NTLMSSP] Kerberos AP-REQ ..."
};

/// Name of a GSS-API mechanism OID (Kerberos 5, MS Kerberos 5, Kerberos 5 user-to-user, NTLMSSP, SPNEGO, IAKerb, NEGOEX), or the OID.
std::string gssMechanismName(const std::string &oid);

/// Decodes the security blob `blob[0..length)`, which lies inside the frame of `ctx`. When `parent` is given (and the mode
/// wants fields) a node for the blob with its parts is added under it. Bounded: nesting of tokens inside tokens at most 3,
/// every list at most 16 entries; nothing is read beyond `length`.
SecurityBlob decodeSecurityBlob(Context &ctx, const uint8_t *blob, size_t length, packet::Field *parent, int depth = 0);

} // namespace dissect
