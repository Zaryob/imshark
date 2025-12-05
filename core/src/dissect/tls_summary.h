#pragma once

// What the load pass concluded about the decryption of TLS records, in the few bytes that fit into a packet summary.
//
// TlsRecordState is the outcome for one TLS record (stored per record in the session tables, see tls_decrypt.h) and,
// merged over the records of a packet, the value of the "tls.decryption_status" display filter field. The packet summary
// keeps it in PacketInfo::reassembled_in of TCP packets: that field is only used by IP fragments (ip_frag == 1), which
// are never decoded as TCP, so a packet that carries TLS can use it without growing PacketInfo.

#include <cstdint>

#include <packet/packet_info.h>

namespace dissect {
    enum class TlsRecordState : uint8_t {
        Clear = 0,          // not protected (hellos, ChangeCipherSpec, TLS 1.2 handshake before the keys change): nothing to decrypt
        Decrypted,          // the AEAD tag matched: the key is right and the plaintext is shown
        TagFailure,         // keys exist but the tag does not verify: wrong key, damaged data or a stale key log (no plaintext)
        NoKey,              // no usable key material for this connection / direction
        UnsupportedSuite,   // version or cipher suite outside the supported table
        Malformed,          // cannot be a protected record (too short / long, bad padding)
        NoBackend,          // this build has no OpenSSL
        CaptureGap,         // TCP data of this direction is missing before the record: the record numbers (and so the nonce) are lost
        NoHandshake,        // the ServerHello was not captured: version and cipher suite are unknown
        EarlyData,          // TLS 1.3 0-RTT application data of the client (encrypted with the early traffic secret: not decrypted)
        StateLost,          // the session table budget was exceeded: the load pass could not keep what it needs
    };

    /// What the decrypted application data of a TLS connection is dissected as.
    enum class TlsInner : uint8_t { Unknown = 0, Http1, Http2 };

    /// Stable lower case name: the value of the "tls.decryption_status" filter field.
    inline const char *tlsStateName(TlsRecordState s) {
        switch (s) {
            case TlsRecordState::Clear: return "clear";
            case TlsRecordState::Decrypted: return "decrypted";
            case TlsRecordState::TagFailure: return "tag_failure";
            case TlsRecordState::NoKey: return "no_key";
            case TlsRecordState::UnsupportedSuite: return "unsupported_suite";
            case TlsRecordState::Malformed: return "malformed";
            case TlsRecordState::NoBackend: return "unavailable";
            case TlsRecordState::CaptureGap: return "capture_gap";
            case TlsRecordState::NoHandshake: return "no_handshake";
            case TlsRecordState::EarlyData: return "early_data";
            case TlsRecordState::StateLost: return "state_lost";
        }
        return "";
    }

    /// One line for the detail tree.
    inline const char *tlsStateText(TlsRecordState s) {
        switch (s) {
            case TlsRecordState::Clear: return "not encrypted";
            case TlsRecordState::Decrypted: return "decrypted (the key is correct: the authentication tag matched)";
            case TlsRecordState::TagFailure: return "wrong key (the authentication tag does not match; no plaintext is shown)";
            case TlsRecordState::NoKey: return "missing key (no key material for this connection)";
            case TlsRecordState::UnsupportedSuite: return "unsupported cipher suite or TLS version";
            case TlsRecordState::Malformed: return "malformed record (cannot be a protected record)";
            case TlsRecordState::NoBackend: return "decryption is not available in this build (no OpenSSL)";
            case TlsRecordState::CaptureGap: return "not decrypted: data of this direction is missing from the capture before this record";
            case TlsRecordState::NoHandshake: return "not decrypted: the ServerHello was not captured (cipher suite unknown)";
            case TlsRecordState::EarlyData: return "TLS 1.3 early data (0-RTT): encrypted with the early traffic secret, not decrypted";
            case TlsRecordState::StateLost: return "state lost: too many TLS records for the session table, decryption was not recorded";
        }
        return "";
    }

    // ---- the packet summary ---------------------------------------------------------------------------------------------
    constexpr uint32_t kTlsSummaryPresent = 0x100;   // bit 8 of PacketInfo::reassembled_in; bits 0..7 are the TlsRecordState

    inline uint32_t tlsSummaryOf(TlsRecordState s) { return s == TlsRecordState::Clear ? 0u : (kTlsSummaryPresent | static_cast<uint32_t>(s)); }

    /// The best news wins: one decrypted record makes the packet "decrypted", otherwise the first protected record counts.
    inline uint32_t mergeTlsSummary(uint32_t current, uint32_t added) {
        if (!(added & kTlsSummaryPresent)) return current;
        if (!(current & kTlsSummaryPresent)) return added;
        return (added & 0xff) == static_cast<uint32_t>(TlsRecordState::Decrypted) ? added : current;
    }

    inline bool hasTlsSummary(const packet::PacketInfo &p) {
        return p.ip_version != 0 && p.ip_protocol == 6 && p.ip_frag != 1 && (p.reassembled_in & kTlsSummaryPresent) != 0;
    }

    inline TlsRecordState tlsSummaryState(const packet::PacketInfo &p) {
        return hasTlsSummary(p) ? static_cast<TlsRecordState>(p.reassembled_in & 0xff) : TlsRecordState::Clear;
    }
} // namespace dissect
