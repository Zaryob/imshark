#pragma once

// The payload chains of IKEv2 (RFC 7296, fragmentation RFC 7383) and IKEv1 / ISAKMP (RFC 2408, RFC 2409, IPsec DOI RFC 2407).
// Everything that is encrypted - an IKEv2 SK or SKF payload, an IKEv1 message with the encryption flag - is labelled and never
// interpreted: there are no keys, and what follows an SK payload is cipher text.

#include <cstddef>
#include <cstdint>
#include <string>

#include <packet/packet_info.h>

namespace dissect {
    /// What walking the chain found out (the same in the summary and in the full pass).
    struct IkePayloadReport {
        std::string malformed;          // non-empty: the chain is damaged (a length below the payload header, or beyond the packet)
        bool notify = false;            // the message carries a Notify payload in the clear ...
        uint16_t notifyType = 0;        // ... the first one's Notify Message Type
        bool encrypted = false;         // an SK / SKF payload (IKEv2) or the encryption flag (IKEv1): the rest is not readable
        bool fragment = false;          // an SKF payload (RFC 7383)
        uint16_t fragmentNumber = 0, fragmentTotal = 0;
    };

    /// Walks the payloads of an IKE message. `body` is the message after the 28 byte ISAKMP header (`size` bytes), `bodyOffset` its
    /// offset in the frame, `version` 1 or 2, `firstPayload` the header's Next Payload and `flags` the header's flags. `parent`
    /// receives the tree nodes (null in the summary pass, which only collects the report). Every node lies inside the body.
    IkePayloadReport dissectIkePayloads(const uint8_t *body, size_t size, size_t bodyOffset, uint8_t version, uint8_t firstPayload,
                                        uint8_t flags, packet::Field *parent);

    /// Name of a payload type ("Security Association (SA)") for the given IKE major version.
    std::string ikePayloadTypeName(uint8_t version, uint8_t payloadType);

    /// Name of an IKEv2 Notify Message Type (RFC 7296 3.10.1 and the IANA registry), "Notify 1234" if unknown.
    std::string ikeV2NotifyName(uint16_t type);
} // namespace dissect
