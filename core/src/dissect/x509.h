#pragma once

// Just enough of X.509 (RFC 5280) DER to describe a certificate in the details tree: who it is for, who issued it,
// when it is valid and which names it covers. Everything is bounds checked; anything unexpected ends the parse.

#include <cstddef>
#include <string>
#include <vector>

namespace dissect {
    struct CertificateSummary {
        bool ok = false;
        std::string subject;               // "C=US, O=Example, CN=www.example.org"
        std::string issuer;
        std::string commonName;            // CN of the subject
        std::string serial;                // hex
        std::string notBefore, notAfter;   // "2026-01-02 03:04:05 UTC"
        std::vector<std::string> dnsNames; // subjectAltName dNSName entries
    };

    CertificateSummary parseCertificate(const unsigned char *der, size_t size);
} // namespace dissect
