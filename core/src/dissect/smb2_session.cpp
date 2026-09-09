#include "smb2_session.h"

#include <algorithm>
#include <cctype>

namespace dissect {

namespace {
constexpr uint64_t kAllOnes = ~0ull;
constexpr uint32_t kNoTree = 0xFFFFFFFFu;

bool endsWithNoCase(const std::string &s, const char *suffix) {
    const std::string x(suffix);
    if (s.size() < x.size()) return false;
    for (size_t i = 0; i < x.size(); ++i)
        if (std::toupper(static_cast<unsigned char>(s[s.size() - x.size() + i])) != std::toupper(static_cast<unsigned char>(x[i]))) return false;
    return true;
}
} // namespace

std::string smb2ConnectionKey(const std::string &ipA, uint16_t portA, const std::string &ipB, uint16_t portB) {
    const std::string a = ipA + ":" + std::to_string(portA), b = ipB + ":" + std::to_string(portB);
    return a < b ? a + "|" + b : b + "|" + a;
}

void Smb2Table::clear() {
    connections_.clear();
    notes_.clear();
    memory_ = 0;
}

void Smb2Table::forgetConnectionState(Connection &c) {
    size_t freed = 0;
    for (const auto &t: c.trees) freed += treeCost(t.second);
    for (const auto &f: c.files) freed += fileCost(f.second);
    for (const auto &p: c.pending) freed += pendingCost(p.second);
    memory_ -= std::min(memory_, freed);
    c.trees.clear();
    c.files.clear();
    c.pending.clear();
}

void Smb2Table::dropFilesOf(Connection &c, uint64_t session, bool anyTree, uint32_t tree) {
    for (auto it = c.files.begin(); it != c.files.end();) {
        if (it->second.session == session && (anyTree || it->second.tree == tree)) {
            memory_ -= std::min(memory_, fileCost(it->second));
            it = c.files.erase(it);
        } else {
            ++it;
        }
    }
}

const Smb2Note *Smb2Table::note(uint32_t packet, int64_t seq, uint8_t index) const {
    const auto it = notes_.find(NoteKey{packet, static_cast<uint32_t>(seq), index});
    return it == notes_.end() ? nullptr : &it->second;
}

const Smb2OpenFile *Smb2Table::openFile(const std::string &connection, uint64_t persistent, uint64_t volatileId) const {
    const auto c = connections_.find(connection);
    if (c == connections_.end()) return nullptr;
    const auto f = c->second.files.find({persistent, volatileId});
    return f == c->second.files.end() ? nullptr : &f->second;
}

const std::string *Smb2Table::share(const std::string &connection, uint64_t session, uint32_t tree) const {
    const auto c = connections_.find(connection);
    if (c == connections_.end()) return nullptr;
    const auto t = c->second.trees.find({session, tree});
    return t == c->second.trees.end() ? nullptr : &t->second.share;
}

const Smb2Note *Smb2Table::observe(const std::string &connection, uint32_t packet, int64_t seq, uint8_t index, const Smb2Command &cmd, size_t maxMemory, bool &lost) {
    const NoteKey key{packet, static_cast<uint32_t>(seq), index};
    if (const auto existing = notes_.find(key); existing != notes_.end()) return &existing->second;

    const auto reserve = [&](size_t bytes) {
        if (memory_ + bytes > maxMemory) { lost = true; return false; }
        memory_ += bytes;
        return true;
    };
    const auto release = [&](size_t bytes) { memory_ -= std::min(memory_, bytes); };

    auto cit = connections_.find(connection);
    if (cit == connections_.end()) {
        if (!reserve(connection.capacity() + sizeof(Connection) + 64)) return nullptr;
        cit = connections_.emplace(connection, Connection{}).first;
    }
    Connection &c = cit->second;
    if (index == 0) {
        c.lastSession = 0;
        c.lastTree = 0;
        c.lastHasFile = false;
        c.lastPersistent = c.lastVolatile = 0;
        c.lastFile.clear();
    }

    Smb2Note n;
    n.command = cmd.command;
    n.infoType = cmd.infoType;
    n.infoClass = cmd.infoClass;
    n.ctlCode = cmd.ctlCode;
    uint64_t session = cmd.sessionId;
    uint32_t tree = cmd.treeId;
    bool hasFile = cmd.hasFileId;
    uint64_t persistent = cmd.filePersistent, volatileId = cmd.fileVolatile;

    if (!cmd.response) {
        if (cmd.command == kSmb2Negotiate) forgetConnectionState(c);
        // related operations take what the command before used
        bool relatedFile = false;
        if (cmd.related && index > 0) {
            if (session == kAllOnes) { session = c.lastSession; n.flags |= Smb2Note::kRelated; }
            if (tree == kNoTree) { tree = c.lastTree; n.flags |= Smb2Note::kRelated; }
            if (hasFile && persistent == kAllOnes && volatileId == kAllOnes) {
                relatedFile = true;
                n.flags |= Smb2Note::kRelated;
                hasFile = c.lastHasFile;
                persistent = c.lastPersistent;
                volatileId = c.lastVolatile;
            }
        }
        if (const auto t = c.trees.find({session, tree}); t != c.trees.end()) {
            n.share = t->second.share;
            if (t->second.pipe) n.flags |= Smb2Note::kPipe;
        }
        if (cmd.command == kSmb2Create) {
            n.file = cmd.name;
        } else if (hasFile) {
            if (const auto f = c.files.find({persistent, volatileId}); f != c.files.end()) {
                n.file = f->second.name;
                if (f->second.pipe) n.flags |= Smb2Note::kPipe;
            }
        } else if (relatedFile) {
            n.file = c.lastFile;
        }
        if (cmd.command == kSmb2TreeConnect) {
            n.share = cmd.name;
            if (endsWithNoCase(cmd.name, "\\IPC$")) n.flags |= Smb2Note::kPipe;
        }

        if (cmd.command != kSmb2Cancel && cmd.messageId != kAllOnes && !c.pending.count(cmd.messageId)) {
            Pending p;
            p.noteKey = key;
            p.command = cmd.command;
            p.session = session;
            p.tree = tree;
            p.hasFileId = hasFile;
            p.filePersistent = persistent;
            p.fileVolatile = volatileId;
            p.name = cmd.name;
            p.share = n.share;
            p.file = n.file;
            p.pipe = (n.flags & Smb2Note::kPipe) != 0;
            p.infoType = cmd.infoType;
            p.infoClass = cmd.infoClass;
            p.ctlCode = cmd.ctlCode;
            if (c.pending.size() >= kMaxPendingPerConnection) {   // the oldest request (lowest MessageId) will not be matched any more
                release(pendingCost(c.pending.begin()->second));
                c.pending.erase(c.pending.begin());
                lost = true;
            }
            if (reserve(pendingCost(p))) c.pending.emplace(cmd.messageId, std::move(p));
        }
        c.lastSession = session;
        c.lastTree = tree;
        c.lastHasFile = hasFile;
        c.lastPersistent = persistent;
        c.lastVolatile = volatileId;
        c.lastFile = n.file;
    } else {
        const bool interim = cmd.status == kSmb2StatusPending;
        const auto pit = cmd.messageId == kAllOnes ? c.pending.end() : c.pending.find(cmd.messageId);
        if (pit != c.pending.end() && pit->second.command == cmd.command) {
            const Pending &p = pit->second;
            n.flags |= Smb2Note::kMatched;
            n.requestPacket = p.noteKey.packet;
            n.share = p.share;
            n.file = p.file;
            n.infoType = p.infoType;
            n.infoClass = p.infoClass;
            n.ctlCode = p.ctlCode;
            if (p.pipe) n.flags |= Smb2Note::kPipe;
            if (interim) {
                n.flags |= Smb2Note::kInterim;
            } else {
                if (cmd.status == 0) {
                    switch (cmd.command) {
                        case kSmb2TreeConnect: {
                            const bool pipe = cmd.shareType == 2 || endsWithNoCase(p.name, "\\IPC$");
                            Tree t{p.name, pipe};
                            const size_t tc = treeCost(t);
                            const auto slot = c.trees.find({session, tree});
                            if (slot != c.trees.end()) { release(treeCost(slot->second)); c.trees.erase(slot); }
                            if (reserve(tc)) c.trees.emplace(std::make_pair(session, tree), std::move(t));
                            n.share = p.name;
                            if (pipe) n.flags |= Smb2Note::kPipe;
                            break;
                        }
                        case kSmb2TreeDisconnect: {
                            if (const auto t = c.trees.find({p.session, p.tree}); t != c.trees.end()) { release(treeCost(t->second)); c.trees.erase(t); }
                            dropFilesOf(c, p.session, false, p.tree);
                            break;
                        }
                        case kSmb2Logoff: {
                            for (auto t = c.trees.begin(); t != c.trees.end();) {
                                if (t->first.first == p.session) { release(treeCost(t->second)); t = c.trees.erase(t); } else { ++t; }
                            }
                            dropFilesOf(c, p.session, true, 0);
                            break;
                        }
                        case kSmb2Create:
                            if (cmd.hasFileId) {
                                Smb2OpenFile f;
                                f.name = p.name;
                                f.share = p.share;
                                f.pipe = p.pipe;
                                f.session = p.session;
                                f.tree = p.tree;
                                f.openedIn = packet;
                                const auto slot = c.files.find({cmd.filePersistent, cmd.fileVolatile});
                                if (slot != c.files.end()) { release(fileCost(slot->second)); c.files.erase(slot); }
                                if (reserve(fileCost(f))) c.files.emplace(std::make_pair(cmd.filePersistent, cmd.fileVolatile), std::move(f));
                            }
                            break;
                        case kSmb2Close: {
                            bool ids = p.hasFileId;
                            uint64_t fp = p.filePersistent, fv = p.fileVolatile;
                            if (!ids && index > 0 && c.lastHasFile) { ids = true; fp = c.lastPersistent; fv = c.lastVolatile; }   // related Close of the Create before it
                            if (ids) {
                                if (const auto f = c.files.find({fp, fv}); f != c.files.end()) { release(fileCost(f->second)); c.files.erase(f); }
                            }
                            break;
                        }
                        default: break;
                    }
                }
                // the request learns that and where it was answered
                if (const auto rn = notes_.find(p.noteKey); rn != notes_.end()) {
                    rn->second.responsePacket = packet;
                    rn->second.flags |= Smb2Note::kAnswered;
                }
                release(pendingCost(p));
                c.pending.erase(pit);
            }
        } else if (cmd.messageId != kAllOnes) {
            n.flags |= Smb2Note::kUnmatched;
            if (const auto t = c.trees.find({session, tree}); t != c.trees.end()) {
                n.share = t->second.share;
                if (t->second.pipe) n.flags |= Smb2Note::kPipe;
            }
        }
        c.lastSession = session;
        c.lastTree = tree;
        if (cmd.hasFileId) {   // a Create response; the responses after it in the message keep its ids
            c.lastHasFile = true;
            c.lastPersistent = cmd.filePersistent;
            c.lastVolatile = cmd.fileVolatile;
        }
        if (!n.file.empty()) c.lastFile = n.file;
    }

    if (!reserve(noteCost(n))) return nullptr;
    return &notes_.emplace(key, std::move(n)).first->second;
}

} // namespace dissect
