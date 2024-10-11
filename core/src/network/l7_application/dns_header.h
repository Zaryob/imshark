//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    struct DNSHeader {
        uint16_t transaction_id;    // Identification number
        uint16_t flags;             // Flags
        uint16_t questions;         // Number of questions
        uint16_t answer_rrs;        // Number of answer resource records
        uint16_t authority_rrs;     // Number of authority resource records
        uint16_t additional_rrs;    // Number of additional resource records
    };
} // namespace network