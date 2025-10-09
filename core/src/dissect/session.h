#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

namespace dissect {

struct SessionTables {
    std::unordered_set<uint16_t> ftpDataPorts;

    struct TftpSession {
        std::string clientIp;
        uint16_t clientPort = 0;
        std::string serverIp;
        uint16_t serverPort = 0; // TID
    };
    std::vector<TftpSession> tftpSessions;
};

} // namespace dissect
