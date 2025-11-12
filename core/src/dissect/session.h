#pragma once

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include <tls/keylog.h>

namespace dissect {

struct TftpSession {
    std::string clientIp;
    uint16_t clientPort = 0;
    std::string serverIp;
    uint16_t serverPort = 0; // TID
};

class SessionTables {
public:
    static constexpr size_t kDefaultMaxMemoryPerTable = 64 * 1024 * 1024; // 64 MB per table upper bound

    explicit SessionTables(size_t maxMemoryPerTable = kDefaultMaxMemoryPerTable)
        : maxMemoryPerTable_(maxMemoryPerTable) {}

    /// Freezes the tables after capture loading. Immutable during packet detail replay.
    void freeze() { frozen_ = true; }
    void unfreeze() { frozen_ = false; }
    bool isFrozen() const { return frozen_; }

    void clear() {
        ftpDataPorts_.clear();
        tftpSessions_.clear();
        ftpMemory_ = 0;
        tftpMemory_ = 0;
        tlsCaptureKeys_.clear();   // the keys the user supplied (tlsExternalKeys) outlive a new capture
        stateLost_ = false;
        stateLostTables_.clear();
        frozen_ = false;
    }

    void setMaxMemoryPerTable(size_t bytes) { maxMemoryPerTable_ = bytes; }
    size_t maxMemoryPerTable() const { return maxMemoryPerTable_; }

    /// Diagnosis: returns true if any session table exceeded its memory budget.
    bool hasStateLost() const { return stateLost_; }
    const std::unordered_set<std::string> &stateLostTables() const { return stateLostTables_; }
    bool isTableStateLost(const std::string &tableName) const { return stateLostTables_.count(tableName) > 0; }

    // ---- FTP Data Connections -------------------------------------------------------------
    bool addFtpDataPort(uint16_t port) {
        if (frozen_) return false;
        if (ftpDataPorts_.count(port)) return true;
        constexpr size_t entrySize = sizeof(uint16_t) + 32; // hash node overhead
        if (ftpMemory_ + entrySize > maxMemoryPerTable_) {
            markStateLost("ftp");
            return false;
        }
        ftpDataPorts_.insert(port);
        ftpMemory_ += entrySize;
        return true;
    }

    bool hasFtpDataPort(uint16_t port) const {
        return ftpDataPorts_.count(port) > 0;
    }

    const std::unordered_set<uint16_t> &ftpDataPorts() const { return ftpDataPorts_; }

    // ---- TFTP Dynamic Port Sessions -------------------------------------------------------
    bool addTftpSession(const std::string &clientIp, uint16_t clientPort,
                        const std::string &serverIp, uint16_t serverPort = 0) {
        if (frozen_) return false;
        const size_t entrySize = sizeof(TftpSession) + clientIp.capacity() + serverIp.capacity() + 16;
        if (tftpMemory_ + entrySize > maxMemoryPerTable_) {
            markStateLost("tftp");
            return false;
        }
        tftpSessions_.push_back({clientIp, clientPort, serverIp, serverPort});
        tftpMemory_ += entrySize;
        return true;
    }

    bool matchOrUpdateTftpSession(uint16_t srcPort, uint16_t dstPort) {
        for (auto &sess : tftpSessions_) {
            if ((sess.clientPort == srcPort && (sess.serverPort == dstPort || sess.serverPort == 0)) ||
                (sess.clientPort == dstPort && (sess.serverPort == srcPort || sess.serverPort == 0))) {
                if (!frozen_ && sess.serverPort == 0) {
                    sess.serverPort = (sess.clientPort == srcPort) ? dstPort : srcPort;
                }
                return true;
            }
        }
        return false;
    }

    std::vector<TftpSession> &tftpSessions() { return tftpSessions_; }
    const std::vector<TftpSession> &tftpSessions() const { return tftpSessions_; }

    // ---- TLS key material (see tls/keylog.h) ----------------------------------------------------
    /// Secrets the user supplied (key log file / text). They stay when clear() starts a new capture.
    tls::KeyStore &tlsExternalKeys() { return tlsExternalKeys_; }
    const tls::KeyStore &tlsExternalKeys() const { return tlsExternalKeys_; }
    /// Secrets that came with the capture (pcapng Decryption Secrets Blocks); cleared with the capture.
    tls::KeyStore &tlsCaptureKeys() { return tlsCaptureKeys_; }
    const tls::KeyStore &tlsCaptureKeys() const { return tlsCaptureKeys_; }

    /// All secrets known for the connection whose ClientHello random is `clientRandom` (both sources merged).
    /// Returns false if there are none.
    bool findTlsKeys(const tls::ClientRandom &clientRandom, tls::KeyEntry &out) const {
        const tls::KeyEntry *a = tlsExternalKeys_.find(clientRandom), *b = tlsCaptureKeys_.find(clientRandom);
        if (!a && !b) return false;
        out = tls::KeyEntry{};
        for (const tls::KeyEntry *e: {b, a}) {   // the user's own keys win
            if (!e) continue;
            for (size_t i = 0; i < tls::kSecretKinds; ++i) if (e->secrets[i].present()) out.secrets[i] = e->secrets[i];
        }
        return true;
    }

    size_t totalMemoryUsage() const { return ftpMemory_ + tftpMemory_; }

private:
    void markStateLost(const std::string &tableName) {
        stateLost_ = true;
        stateLostTables_.insert(tableName);
    }

    size_t maxMemoryPerTable_ = kDefaultMaxMemoryPerTable;
    bool frozen_ = false;
    bool stateLost_ = false;
    std::unordered_set<std::string> stateLostTables_;

    std::unordered_set<uint16_t> ftpDataPorts_;
    size_t ftpMemory_ = 0;

    std::vector<TftpSession> tftpSessions_;
    size_t tftpMemory_ = 0;

    tls::KeyStore tlsExternalKeys_;
    tls::KeyStore tlsCaptureKeys_;
};

} // namespace dissect

namespace core {
    using SessionTables = dissect::SessionTables;
    using TftpSession = dissect::TftpSession;
}
