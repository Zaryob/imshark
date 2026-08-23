#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <packet/ethernet_table.h>
#include <packet/ipsec_table.h>
#include <tls/keylog.h>

#include "dtls_decrypt.h"
#include "sctp_session.h"
#include "tls_decrypt.h"
#include "tls_session.h"

namespace dissect {

struct TftpSession {
    std::string clientIp;
    uint16_t clientPort = 0;
    std::string serverIp;
    uint16_t serverPort = 0; // TID
};

/// The setup packet of a USB control request (USB 2.0 spec 9.3), remembered so that its completion can be decoded.
struct UsbControlRequest {
    uint8_t bmRequestType = 0;
    uint8_t bRequest = 0;
    uint16_t wValue = 0;
    uint16_t wIndex = 0;
    uint16_t wLength = 0;
    /// Standard GET_DESCRIPTOR request (device to host, bRequest 6): the completion carries descriptors.
    bool isGetDescriptor() const { return bRequest == 6 && (bmRequestType & 0xE0) == 0x80; }
};

/// One Bluetooth ACL connection as the HCI events announced it: the controller's connection handle belongs to a BD_ADDR from the
/// packet that completed the connection until the packet that ended it (a handle is reused after a disconnect).
struct BluetoothLink {
    std::array<uint8_t, 6> address{};   // as on the wire (least significant byte first)
    uint32_t from = 0;                  // number of the connection complete event
    uint32_t to = UINT32_MAX;           // number of the disconnection complete event (exclusive); UINT32_MAX = still open
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
        tls_.clear();
        tlsDecrypt_.clear();
        dtls_.clear();
        sctp_.clear();
        tlsCaptureKeys_.clear();   // the keys the user supplied (tlsExternalKeys) outlive a new capture
        tlsUpgrades_.clear();
        serverEndpoints_.clear();
        connectionMemory_ = 0;
        usbOpen_.clear();
        usbDone_.clear();
        usbMemory_ = 0;
        btLinks_.clear();
        btMemory_ = 0;
        ethernet_.clear();
        ipsec_.clear();
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

    // ---- TLS connections (see tls_session.h) ------------------------------------------------
    /// Registers one TCP message of a TLS connection (load pass only; `src` -> `dst` is the direction it travels).
    /// Returns false if the tables are frozen or the memory budget is exhausted (then the "tls" table is state lost).
    /// `result` (optional) says where the message went, for decryptTlsMessage().
    bool addTlsMessage(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                       const TlsMessageFacts &facts, TlsAddResult *result = nullptr) {
        if (result) *result = TlsAddResult{};
        if (frozen_) return false;
        const size_t decryptMemory = std::min(tlsDecrypt_.memory(), maxMemoryPerTable_);   // the "tls" budget covers the outcomes too
        if (!tls_.add(srcIp, srcPort, dstIp, dstPort, facts, maxMemoryPerTable_ - decryptMemory, result)) {
            markStateLost("tls");
            return false;
        }
        return true;
    }

    /// Load pass, right after addTlsMessage() registered a message: opens its `records` (in stream order, per direction)
    /// when key material for the connection is known, records one outcome per record and fills `out` with the outcomes and
    /// the plaintext of the decrypted ones. Without key material nothing is stored and `out` holds the states derived from
    /// the session tables. Returns false (and marks "tls" state lost) if the budget is exceeded; `out` is then empty.
    bool decryptTlsMessage(const TlsAddResult &added, uint32_t packet, uint32_t startSeq, std::span<const TlsRecordInput> records,
                           TlsMessageDecryption &out) {
        out = TlsMessageDecryption{};
        if (frozen_ || !added.registered) return false;
        TlsSession *session = tls_.mutableSession(added.session);
        if (!session) return false;
        tls::KeyEntry entry;
        if (!(session->hasClientRandom && findTlsKeys(session->clientRandom, entry))) {
            readTlsMessage(TlsMessageRef{added.session, added.direction, added.firstRecord, static_cast<uint32_t>(records.size()), kTlsNoRecord}, records, out);
            return true;
        }
        uint32_t first = kTlsNoRecord;
        const size_t room = maxMemoryPerTable_ > tls_.memory() ? maxMemoryPerTable_ - tls_.memory() : 0;
        if (!tlsDecrypt_.process(*session, added.session, added.direction, added.firstRecord, added.gapBefore, records, &entry, room, first, out)) {
            out = TlsMessageDecryption{};
            markStateLost("tls");
            return false;
        }
        tls_.setFirstOutcome(packet, startSeq, first);
        return true;
    }

    /// Detail building (and the load pass for a message whose decryption it could not record): the outcomes of the `records`
    /// of a registered message and the re-opened plaintext of the decrypted ones. A message of a keyed connection that was
    /// not recorded (the "tls" budget ran out) reads as state lost.
    void readTlsMessage(const TlsMessageRef &ref, std::span<const TlsRecordInput> records, TlsMessageDecryption &out) const {
        out = TlsMessageDecryption{};
        const TlsSession *session = tls_.session(ref.session);
        if (!session) return;
        tls::KeyEntry entry;
        const bool found = session->hasClientRandom && findTlsKeys(session->clientRandom, entry);
        tlsDecrypt_.read(*session, ref, records, found ? &entry : nullptr, out);
    }
    const TlsDecryptTable &tlsDecryptTable() const { return tlsDecrypt_; }

    /// The message that the packet `packet` completed (or lies in) and that starts at relative sequence number `startSeq`.
    const TlsMessageRef *findTlsMessage(uint32_t packet, uint32_t startSeq) const { return tls_.findMessage(packet, startSeq); }
    const TlsSession *tlsSession(uint32_t id) const { return tls_.session(id); }
    /// The newest TLS session between two endpoints; `direction` (optional) is the TlsSession::directions index of
    /// the traffic from the first endpoint to the second.
    const TlsSession *findTlsSession(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                                     unsigned *direction = nullptr) const {
        return tls_.find(srcIp, srcPort, dstIp, dstPort, direction);
    }
    size_t tlsSessionsBetween(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort) const {
        return tls_.sessionsBetween(srcIp, srcPort, dstIp, dstPort);
    }
    /// Load pass: a SYN (without ACK) from src to dst went by. Endpoints that already have a TLS session expect a new
    /// connection whose first message starts at `firstSeq` (relative sequence number behind the SYN). Frozen tables
    /// ignore it; a marker that does not fit the budget marks the "tls" table state lost.
    bool markTlsRestart(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint32_t firstSeq) {
        if (frozen_) return false;
        if (!tls_.markRestart(srcIp, srcPort, dstIp, dstPort, firstSeq, maxMemoryPerTable_)) {
            markStateLost("tls");
            return false;
        }
        return true;
    }
    /// True if a message starting at `startSeq` continues the latest session and its direction already changed keys.
    bool tlsDirectionEncrypted(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                               uint32_t startSeq) const {
        return tls_.continuesEncrypted(srcIp, srcPort, dstIp, dstPort, startSeq);
    }
    const TlsSessionTable &tlsTable() const { return tls_; }

    // ---- TCP connections that switch to TLS in the middle (LDAP StartTLS, PostgreSQL SSLRequest, MySQL SSL) ------------
    // Decided while the capture loads, from the message that agrees to the switch; Replay only reads. A direction is
    // identified like the TCP stream tables do (src:port>dst:port), the mark is the relative sequence number of the first
    // byte that is TLS. The stream dispatcher (tcp.cpp) hands TLS to the TLS dissector from there on, whatever the port
    // registered, and does not let the port's own dissector mis-decode encrypted bytes.
    /// Load pass: bytes of the direction src -> dst from relative sequence number `fromSeq` on are TLS. The first mark of a
    /// direction wins. Returns false if frozen or out of budget (then the "tls-upgrade" table is state lost).
    bool markTlsUpgrade(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint32_t fromSeq) {
        if (frozen_) return false;
        const std::string key = directionKey(srcIp, srcPort, dstIp, dstPort);
        if (tlsUpgrades_.count(key)) return true;
        const size_t entrySize = key.capacity() + sizeof(uint32_t) + 48;
        if (connectionMemory_ + entrySize > maxMemoryPerTable_) {
            markStateLost("tls-upgrade");
            return false;
        }
        tlsUpgrades_.emplace(key, fromSeq);
        connectionMemory_ += entrySize;
        return true;
    }
    /// True if the byte at relative sequence number `seq` of the direction src -> dst is part of a TLS connection that was
    /// switched to TLS (see markTlsUpgrade).
    bool isTlsUpgraded(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint32_t seq) const {
        if (tlsUpgrades_.empty()) return false;
        const auto it = tlsUpgrades_.find(directionKey(srcIp, srcPort, dstIp, dstPort));
        return it != tlsUpgrades_.end() && static_cast<int32_t>(seq - it->second) >= 0;
    }
    /// Load pass: a new connection (SYN) between the endpoints forgets the switch of an earlier one.
    void forgetTlsUpgrade(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort) {
        if (frozen_ || tlsUpgrades_.empty()) return;
        for (const std::string &key: {directionKey(srcIp, srcPort, dstIp, dstPort), directionKey(dstIp, dstPort, srcIp, srcPort)}) {
            const auto it = tlsUpgrades_.find(key);
            if (it == tlsUpgrades_.end()) continue;
            connectionMemory_ -= std::min(connectionMemory_, it->first.capacity() + sizeof(uint32_t) + 48);
            tlsUpgrades_.erase(it);
        }
    }

    // ---- Database servers on a port other than the default (MySQL: told by the server greeting) -------------------------
    /// Load pass: the endpoint ip:port sent a server greeting, so it is the server side of its connections.
    bool markServerEndpoint(const std::string &ip, uint16_t port) {
        if (frozen_) return false;
        const std::string key = ip + ":" + std::to_string(port);
        if (serverEndpoints_.count(key)) return true;
        const size_t entrySize = key.capacity() + 48;
        if (connectionMemory_ + entrySize > maxMemoryPerTable_) {
            markStateLost("server-endpoints");
            return false;
        }
        serverEndpoints_.insert(key);
        connectionMemory_ += entrySize;
        return true;
    }
    bool isServerEndpoint(const std::string &ip, uint16_t port) const {
        return !serverEndpoints_.empty() && serverEndpoints_.count(ip + ":" + std::to_string(port)) > 0;
    }

    // ---- USB control transfers ---------------------------------------------------------------------------------------
    /// Load pass: a control request (URB submit / USBPcap setup stage) with this URB or IRP id went by.
    bool addUsbRequest(uint64_t urbId, const UsbControlRequest &request) {
        if (frozen_) return false;
        const size_t entrySize = sizeof(uint64_t) + sizeof(UsbControlRequest) + 48;
        if (usbMemory_ + entrySize > maxMemoryPerTable_) {
            markStateLost("usb");
            return false;
        }
        if (usbOpen_.insert_or_assign(urbId, request).second) usbMemory_ += entrySize;
        return true;
    }
    /// Load pass: packet `packet` completes the request with this id (the request is consumed).
    bool completeUsbRequest(uint64_t urbId, uint32_t packet) {
        if (frozen_) return false;
        const auto it = usbOpen_.find(urbId);
        if (it == usbOpen_.end()) return false;
        const size_t entrySize = sizeof(uint32_t) + sizeof(UsbControlRequest) + 48;
        if (usbMemory_ + entrySize > maxMemoryPerTable_) {
            markStateLost("usb");
            return false;
        }
        usbDone_[packet] = it->second;
        usbMemory_ += entrySize;
        usbOpen_.erase(it);
        return true;
    }
    /// The request that packet `packet` completed (nullptr if it completed none or the request was never seen).
    const UsbControlRequest *usbRequestOf(uint32_t packet) const {
        const auto it = usbDone_.find(packet);
        return it == usbDone_.end() ? nullptr : &it->second;
    }

    // ---- DTLS connections (see dtls_session.h) -----------------------------------------------
    /// Load pass: a complete ClientHello / ServerHello went by from src to dst. Returns false if the tables are frozen or
    /// the budget is exhausted (then the "dtls" table is state lost).
    bool addDtlsHello(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const DtlsHelloFacts &facts) {
        if (frozen_) return false;
        if (!dtls_.addHello(srcIp, srcPort, dstIp, dstPort, facts, maxMemoryPerTable_)) {
            markStateLost("dtls");
            return false;
        }
        return true;
    }

    /// Load pass: one handshake fragment (of the packet and position in `fragment`). `earlierPackets` receives, when the
    /// fragment completes a message, the other packets that carried its fragments. Returns false if frozen or out of room.
    bool addDtlsFragment(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const DtlsFragment &fragment,
                         std::vector<uint32_t> &earlierPackets) {
        earlierPackets.clear();
        if (frozen_) return false;
        if (!dtls_.addFragment(srcIp, srcPort, dstIp, dstPort, fragment, maxMemoryPerTable_, earlierPackets)) {
            markStateLost("dtls");
            return false;
        }
        return true;
    }
    const DtlsFragmentRef *dtlsFragment(uint32_t packet, uint16_t position) const { return dtls_.fragment(packet, position); }
    const DtlsMessage *dtlsMessage(uint32_t index) const { return dtls_.message(index); }
    const DtlsSession *dtlsSession(uint32_t id) const { return dtls_.session(id); }
    /// The latest DTLS session between two endpoints (kDtlsNone: none); `direction` as in DtlsTable::find().
    uint32_t findDtlsSession(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, unsigned *direction = nullptr) const {
        return dtls_.find(srcIp, srcPort, dstIp, dstPort, direction);
    }

    /// What became of one protected DTLS record.
    struct DtlsRecordResult {
        TlsRecordState state = TlsRecordState::NoKey;
        uint32_t session = kDtlsNone;
        std::vector<uint8_t> plaintext;          // only when Decrypted
    };

    /// Load pass: opens the protected record `in` of the packet (at `position` in the UDP payload) travelling src -> dst with
    /// the keys of the latest session of those endpoints, and records the outcome. Returns false (and marks "dtls" state
    /// lost, `out.state` = StateLost) if the outcome did not fit the budget or the tables are frozen.
    bool decryptDtlsRecord(uint32_t packet, uint16_t position, const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                           const DtlsRecordInput &in, DtlsRecordResult &out) {
        out = DtlsRecordResult{};
        if (frozen_) return false;
        unsigned direction = 0;
        const uint32_t id = dtls_.find(srcIp, srcPort, dstIp, dstPort, &direction);
        DtlsRecordOutcome o;
        o.session = id;
        TlsRecordState state = TlsRecordState::NoKey;
        if (DtlsSession *s = dtls_.mutableSession(id)) {
            o.fromClient = s->clientDirection >= 0 && static_cast<unsigned>(s->clientDirection) == direction;
            tls::KeyEntry entry;
            const bool found = s->hasClientRandom && findTlsKeys(s->clientRandom, entry);
            if (const auto why = prepareDtlsKeys(*s, found ? &entry : nullptr)) state = *why;
            else state = openDtlsRecord(*s, o.fromClient, in, out.plaintext);
        }
        o.state = static_cast<uint8_t>(state);
        o.plainLength = static_cast<uint32_t>(out.plaintext.size());
        out.state = state;
        out.session = id;
        if (!dtls_.addOutcome(packet, position, o, maxMemoryPerTable_)) {
            markStateLost("dtls");
            out = DtlsRecordResult{};
            out.state = TlsRecordState::StateLost;
            return false;
        }
        return true;
    }

    /// Detail building: the recorded outcome of that record, and the plaintext re-opened with the session's keys when it was
    /// decrypted. A record without an outcome reads as state lost when the table lost state, otherwise as missing key.
    void readDtlsRecord(uint32_t packet, uint16_t position, const DtlsRecordInput &in, DtlsRecordResult &out) const {
        out = DtlsRecordResult{};
        const DtlsRecordOutcome *o = dtls_.outcome(packet, position);
        if (!o) {
            out.state = isTableStateLost("dtls") ? TlsRecordState::StateLost : TlsRecordState::NoKey;
            return;
        }
        out.state = o->recordState();
        out.session = o->session;
        const DtlsSession *s = dtls_.session(o->session);
        if (out.state == TlsRecordState::Decrypted && (!s || openDtlsRecord(*s, o->fromClient, in, out.plaintext) != TlsRecordState::Decrypted)) {
            out.state = TlsRecordState::Malformed;   // cannot happen: the load pass opened this record with these keys
            out.plaintext.clear();
        }
    }
    const DtlsTable &dtlsTable() const { return dtls_; }

    // ---- SCTP associations (see sctp_session.h) -------------------------------------------------
    /// Load pass: takes one DATA / I-DATA fragment for reassembly. Returns false if frozen or out of budget; the "sctp" table is
    /// marked state lost when it ran out of room or had to drop an incomplete message.
    bool addSctpFragment(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const SctpFragment &fragment,
                         std::vector<uint32_t> &earlierPackets) {
        if (frozen_) return false;
        const auto result = sctp_.addFragment(srcIp, srcPort, dstIp, dstPort, fragment, maxMemoryPerTable_, earlierPackets);
        if (!result.kept || result.evicted) markStateLost("sctp");
        return result.kept;
    }
    /// Load pass: counts a DATA / I-DATA chunk in its stream's totals.
    bool noteSctpData(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint16_t stream, size_t bytes, bool endsMessage,
                      uint32_t packet, uint16_t position) {
        if (frozen_) return false;
        if (!sctp_.noteData(srcIp, srcPort, dstIp, dstPort, stream, bytes, endsMessage, packet, position, maxMemoryPerTable_)) {
            markStateLost("sctp");
            return false;
        }
        return true;
    }
    const SctpFragmentRef *sctpFragment(uint32_t packet, uint16_t position) const { return sctp_.fragment(packet, position); }
    const SctpMessage *sctpMessage(uint32_t index) const { return sctp_.message(index); }
    const SctpTable &sctpTable() const { return sctp_; }

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

    // ---- Bluetooth connections ---------------------------------------------------------------------------------------
    /// Key of a connection: the controller (Linux monitor adapter id, 0xFFFF for H4 captures) and the 12 bit handle.
    static uint32_t bluetoothLinkKey(uint16_t adapter, uint16_t handle) { return (static_cast<uint32_t>(adapter) << 16) | (handle & 0x0FFF); }

    /// Load pass: packet `number` completed a connection (Connection Complete / LE Connection Complete). An open connection
    /// on the same handle (its disconnection was not captured) ends here. Returns false if frozen or out of budget
    /// (then the "bluetooth" table is state lost and later ACL packets of that handle keep their handle as address).
    bool openBluetoothLink(uint32_t key, const uint8_t *address, uint32_t number) {
        if (frozen_) return false;
        const size_t entrySize = sizeof(BluetoothLink) + 32;
        if (btMemory_ + entrySize > maxMemoryPerTable_) {
            markStateLost("bluetooth");
            return false;
        }
        auto &links = btLinks_[key];
        if (!links.empty() && links.back().to == UINT32_MAX) links.back().to = number;
        BluetoothLink link;
        std::copy(address, address + 6, link.address.begin());
        link.from = number;
        links.push_back(link);
        btMemory_ += entrySize;
        return true;
    }
    /// Load pass: packet `number` is a Disconnection Complete for this handle.
    bool closeBluetoothLink(uint32_t key, uint32_t number) {
        if (frozen_) return false;
        const auto it = btLinks_.find(key);
        if (it == btLinks_.end() || it->second.empty() || it->second.back().to != UINT32_MAX) return false;
        it->second.back().to = number;
        return true;
    }
    /// The BD_ADDR (wire order) of the connection `key` at packet `number`, or nullptr when no connection event was seen for
    /// it. Both the load pass and Replay read it the same way, so a summary and its details agree.
    const std::array<uint8_t, 6> *bluetoothAddressOf(uint32_t key, uint32_t number) const {
        const auto it = btLinks_.find(key);
        if (it == btLinks_.end()) return nullptr;
        for (auto l = it->second.rbegin(); l != it->second.rend(); ++l) {
            if (l->from < number && number < l->to) return &l->address;
        }
        return nullptr;
    }

    // ---- Ethernet addresses --------------------------------------------------------------------------------------------
    /// Load pass: packet `number` is an Ethernet frame from `source` to `destination` (6 bytes each). Returns false if the tables
    /// are frozen or the memory budget is exhausted (then the "ethernet" table is state lost and statistics fall back to the summary).
    bool addEthernetAddresses(uint32_t number, const uint8_t *source, const uint8_t *destination) {
        if (frozen_) return false;
        if (ethernet_.memory() + sizeof(packet::EthernetAddressTable::Entry) > maxMemoryPerTable_) {
            markStateLost("ethernet");
            return false;
        }
        return ethernet_.add(number, source, destination, SIZE_MAX);
    }
    const packet::EthernetAddressTable &ethernetAddresses() const { return ethernet_; }

    // ---- IPsec headers ------------------------------------------------------------------------------------------------
    /// Load pass: packet `number` has an AH (`kinds` packet::IpsecTable::kAh) or ESP (kEsp, with kEspPlaintext when the payload was
    /// dissected as unencrypted) header with this SPI and sequence number.
    /// Returns false if the tables are frozen or the memory budget is exhausted (then the "ipsec" table is state lost and the
    /// ah.* / esp.* values are missing for the later packets).
    bool addIpsecHeader(uint32_t number, uint8_t kinds, uint32_t spi, uint32_t sequence) {
        if (frozen_) return false;
        if (ipsec_.memory() + sizeof(packet::IpsecTable::Entry) > maxMemoryPerTable_) {
            markStateLost("ipsec");
            return false;
        }
        return ipsec_.add(number, kinds, spi, sequence, SIZE_MAX);
    }
    const packet::IpsecTable &ipsecHeaders() const { return ipsec_; }

    /// The ESP-NULL heuristic (esp_null.h) is a user setting and off by default: a wrong guess would show protocol content that is
    /// not there. The load pass reads it; the detail view reads what the load pass decided (packet::IpsecTable::kEspPlaintext). It
    /// is part of the settings, not of the capture: clear() keeps it.
    void setEspNullHeuristic(bool on) { espNullHeuristic_ = on; }
    bool espNullHeuristic() const { return espNullHeuristic_; }

    size_t totalMemoryUsage() const { return ftpMemory_ + tftpMemory_ + connectionMemory_ + usbMemory_ + btMemory_ + tls_.memory() + tlsDecrypt_.memory() + dtls_.memory(); }

private:
    static std::string directionKey(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort) {
        return srcIp + ":" + std::to_string(srcPort) + ">" + dstIp + ":" + std::to_string(dstPort);
    }

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

    std::unordered_map<std::string, uint32_t> tlsUpgrades_;
    std::unordered_set<std::string> serverEndpoints_;
    size_t connectionMemory_ = 0;

    std::unordered_map<uint64_t, UsbControlRequest> usbOpen_;      // requests waiting for their completion
    std::unordered_map<uint32_t, UsbControlRequest> usbDone_;      // completing packet number -> its request
    size_t usbMemory_ = 0;

    std::unordered_map<uint32_t, std::vector<BluetoothLink>> btLinks_;   // by bluetoothLinkKey
    size_t btMemory_ = 0;

    packet::EthernetAddressTable ethernet_;
    packet::IpsecTable ipsec_;
    bool espNullHeuristic_ = false;

    TlsSessionTable tls_;
    TlsDecryptTable tlsDecrypt_;
    DtlsTable dtls_;
    SctpTable sctp_;
    tls::KeyStore tlsExternalKeys_;
    tls::KeyStore tlsCaptureKeys_;
};

} // namespace dissect

namespace core {
    using SessionTables = dissect::SessionTables;
    using TftpSession = dissect::TftpSession;
}
