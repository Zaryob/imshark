#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include <capture/live_capture.h>
#include <core.h>
#include <filter/filter.h>
#include <packet/packet_info.h>
#include <capture_info.h>
#include <dissect/registry.h>
#include <dissect/session.h>
#include <export/export.h>
#include <stats/statistics.h>

#include "color_rules.h"
#include "find.h"
#include <tls/keylog.h>

#include "follow_view.h"
#include "settings.h"

namespace ui {
    struct LoadJob;    // background load in progress (loader.cpp)
    struct SearchJob;  // background byte search in progress (find_bar.cpp)
    struct FollowJob;  // background stream reassembly in progress (follow_window.cpp)
    struct ExportJob;  // background export in progress (export_dialog.cpp)

    /// The display filter bar: what is typed, what is applied, and which packets pass.
    struct FilterState {
        std::string text;                  // contents of the filter bar (edited live)
        std::string previewText;           // `text` the preview below was compiled from
        bool previewOk = true;             // does `text` compile?
        filter::Error previewError;
        std::string appliedText;           // the filter that is active
        filter::Filter applied;
        bool active = false;               // a non-empty filter is applied
        std::vector<uint32_t> visible;     // indices of packets that pass (valid when active)
        bool focusRequested = false;       // put the keyboard cursor into the bar next frame
        bool showHelp = false;
        std::string helpSearch;            // search box of the reference window
    };

    /// The "Find Packet" bar (Ctrl+F).
    struct FindState {
        bool open = false;
        bool focusRequested = false;
        FindMode mode = FindMode::Text;
        std::string text;
        std::string message;      // result of the last search ("Found ...", "No match", filter error)
        bool messageIsError = false;
        std::shared_ptr<SearchJob> job;   // non-null while a byte search runs in the background
    };

    /// The Statistics windows and their cached results (recomputed lazily when `dirty`).
    struct StatsState {
        bool showHierarchy = false, showConversations = false, showEndpoints = false, showExpert = false;
        bool limitToDisplayed = true;      // count only the packets that pass the display filter
        bool dirty = true;                 // capture or filter changed: caches are stale
        int tab = 0;                       // AddressKind tab that was drawn last in the Conversations / Endpoints windows
        int selectTab = -1;                // request to switch to this tab (then reset)

        std::vector<stats::ExpertItem> expert;
        bool expertValid = false;
        stats::HierarchyNode hierarchy;
        bool hierarchyValid = false;
        std::vector<stats::Conversation> conversations[stats::kAddressKindCount];
        bool conversationsValid[stats::kAddressKindCount] = {false};
        std::vector<stats::Endpoint> endpoints[stats::kAddressKindCount];
        bool endpointsValid[stats::kAddressKindCount] = {false};
    };

    /// The Follow Stream window.
    struct FollowState {
        bool open = false;
        std::shared_ptr<FollowJob> job;    // non-null while the stream is being reassembled
        bool valid = false;                // `stream` holds a result
        stream::Stream stream;
        std::string title;
        std::string error;
        FollowView view = FollowView::Ascii;
        FollowDirection direction = FollowDirection::Both;
        FollowStreamMode mode = FollowStreamMode::Tcp;   // the encrypted stream as captured, or its decrypted TLS application data
        stream::Stream plain;              // TCP: the decrypted application data (valid when `tlsOk`)
        stream::TlsStreamResult tls;       // what the decryption found (its note explains an empty `plain`)
        bool tlsOk = false;
        std::vector<FollowLine> lines;     // what is drawn (rebuilt when stream/direction/view change)
        bool linesDirty = true;
    };

    /// The Preferences window (Edit > Preferences...).
    struct PreferencesState {
        bool open = false;
        bool wasOpen = false;              // to detect "just opened"
        std::string tlsKeyLogEdit;         // the text field of the TLS key log file
    };

    /// The Export Packets dialog.
    struct ExportState {
        enum Range { All = 0, Displayed = 1, Selected = 2 };
        bool openPopup = false;            // request to open the options popup
        int range = Displayed;
        int format = 0;                    // index into the list of exporter::Format (see export_dialog.cpp)
        std::shared_ptr<ExportJob> job;    // non-null while an export runs
        std::string resultMessage;         // shown in a popup after the export finished
        bool resultIsError = false;
        bool showResult = false;
    };

    /// The packets of the open capture, shared with background jobs. A job takes a snapshot with share();
    /// replacing or clearing the list only swaps the pointer, so a job that is still running keeps reading
    /// the old, unchanged data and can never see it freed or modified. The only in-place modification is
    /// modify() (a live capture appends to the list): it first makes the list unique, i.e. copies it if a job
    /// still holds a snapshot, so a snapshot is never changed under its reader.
    ///
    /// Threading contract: the list object itself (assign, clear, share) belongs to the UI thread. A worker
    /// receives the snapshot from the UI thread when it is started and only ever touches that snapshot.
    class PacketList {
    public:
        using Vector = std::vector<packet::PacketInfo>;

        PacketList() : data_(std::make_shared<Vector>()) {}

        size_t size() const { return data_->size(); }
        bool empty() const { return data_->empty(); }
        const packet::PacketInfo &operator[](size_t i) const { return (*data_)[i]; }
        const packet::PacketInfo &at(size_t i) const { return data_->at(i); }
        const packet::PacketInfo &front() const { return data_->front(); }
        const packet::PacketInfo &back() const { return data_->back(); }
        Vector::const_iterator begin() const { return data_->begin(); }
        Vector::const_iterator end() const { return data_->end(); }
        operator const Vector &() const { return *data_; }

        void clear() { data_ = std::make_shared<Vector>(); }
        void assign(Vector &&packets) { data_ = std::make_shared<Vector>(std::move(packets)); }

        /// Mutable access for appending live packets (and amending earlier summaries). Copy on write: if a
        /// background job still holds a snapshot, the list is copied first so the job keeps its unchanged data.
        /// Only the UI thread calls share() and modify(), so use_count() cannot grow behind our back.
        Vector &modify() {
            if (data_.use_count() > 1) data_ = std::make_shared<Vector>(*data_);
            return *data_;
        }

        /// Snapshot for a background job: stays valid and unchanged for as long as the job holds it.
        std::shared_ptr<const Vector> share() const { return data_; }

    private:
        std::shared_ptr<Vector> data_;
    };

    /// One Decode As rule: the application protocol to use for a TCP or UDP port.
    struct DecodeAsRule {
        bool tcp = true;
        int port = 0;
        std::string protocol;
        bool operator==(const DecodeAsRule &o) const { return tcp == o.tcp && port == o.port && protocol == o.protocol; }
    };

    /// The Decode As window and the rules in effect.
    struct DecodeAsState {
        bool open = false;
        bool wasOpen = false;                // to copy `rules` into `edit` when the window opens
        std::vector<DecodeAsRule> rules;     // in effect (the capture was loaded with them)
        std::vector<DecodeAsRule> edit;      // working copy in the window
        std::string error;
    };

    /// What the Capture > Interfaces dialog shows and the capture options remembered between sessions.
    struct CaptureDialog {
        bool open = false;
        bool needsRefresh = true;               // read the interface list when the dialog is drawn
        capture::InterfaceList interfaces;
        bool listLoaded = false;
        capture::FilterCheck filterCheck;        // result of validating `options.filter`
        std::string checkedFilter;              // what filterCheck was computed for
        uint32_t checkedLinkType = 0;
        uint32_t checkedSnaplen = 0;
        bool filterChecked = false;
    };

    /// What to do once the user decided what happens to an unsaved live capture.
    struct PendingAction {
        enum Kind { None, Start, Restart, Open, Close, Quit };
        Kind kind = None;
        std::string path;                       // Open
    };

    /// Live capture: the capture device, the dissector of the running capture and everything the UI needs around it.
    /// The packets themselves live in AppState::packets like those of an opened file; while capturing the poll
    /// (pollCapture) appends the packets that arrived since the last frame, and after stop the capture simply
    /// stays open as a file whose temporary pcap is owned by AppState::tempFile.
    struct LiveState {
        std::unique_ptr<capture::LiveCapture> elevated;     // helper session (pkexec / osascript) until its first packets arrive
        capture::CaptureOptions deniedOptions;              // the start that failed with a permission error (what the helper repeats)
        bool permissionDenied = false;                      // the last failed start was a permission error (structured, from LiveCapture)
        bool openAuthorize = false;                         // show the "waiting for authorization" popup next frame
        bool setupOpen = false;                             // the "Permanent capture setup" window
        /// Test seam: replaces LiveCapture::startElevated, so that tests never start pkexec / osascript.
        std::function<bool(capture::LiveCapture &, const capture::CaptureOptions &)> elevatedStarter;
        std::unique_ptr<capture::LiveCapture> device;       // created on first use (runs a thread while capturing)
        std::unique_ptr<core::FileProcessor> processor;     // dissects the packets of the running capture; null otherwise
        capture::CaptureOptions options;                    // what Start uses (remembered in the settings)
        bool session = false;                               // the open capture came from a live capture (running or stopped)
        bool unsaved = false;                               // ... and its packets were not exported yet
        std::string interfaceName;                          // of the session (status bar)
        bool autoScroll = true;                             // keep the newest packet in view while capturing
        bool scrollToEnd = false;                           // new packets arrived: the list scrolls down next frame
        bool injected = false;                              // the session was fed through the test seam (no device: no Restart)
        capture::CaptureOptions sessionOptions;             // what the session was started with (Restart)
        bool statsPending = false;                          // packets arrived since the statistics were last marked stale
        std::chrono::steady_clock::time_point lastStats = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point lastSortRebuild = std::chrono::steady_clock::now();
        std::string error;                                  // last start/capture error (status bar)
        bool openError = false;                             // show the error popup next frame
        bool errorIsStop = false;                           // the capture ended on its own (vs. could not start)
        CaptureDialog dialog;
        PendingAction pending;                              // waiting for the unsaved-capture decision
        bool openConfirm = false;                           // show the unsaved-capture popup next frame

        bool capturing() const { return device && processor && device->running(); }
    };

    /// Everything the UI needs to remember between frames.
    struct AppState {
        PacketList packets;

        AppState() = default;
        AppState(const AppState &) = delete;
        AppState &operator=(const AppState &) = delete;
        ~AppState();               // removes the temporary decompressed copy, if any

        // Load status
        std::string currentFile;   // the file the packets are read from (a temporary copy for .gz); empty = nothing open
        std::string displayName;   // the file the user opened (what is shown and remembered)
        std::string tempFile;      // non-empty: `currentFile` is a temporary decompressed copy that must be deleted
        std::string loadMessage;   // problem reported by the last load (empty when clean)
        bool loadFailed = false;   // the last load produced no usable capture
        bool openLoadError = false; // show the error popup on the next frame

        std::shared_ptr<LoadJob> loadJob;   // non-null while a capture is being loaded in the background

        bool loading() const { return loadJob != nullptr; }

        // Selection
        int selectedPacket = -1;                        // index into `packets`, -1 = none
        // Full view (raw bytes + field tree) of the selected packet, rebuilt from the file when the selection
        // changes; `packets` only holds summaries. `detailIndex` is the packet `detail` was built for.
        packet::PacketInfo detail;
        int detailIndex = -1;
        bool detailOk = false;
        const packet::Field *selectedField = nullptr;    // field picked in the details tree (points into the packet)
        int selectionStart = -1;                         // highlighted byte range in the hex view (inclusive)
        int selectionEnd = -1;
        bool revealSelectedField = false;                // expand the tree down to `selectedField` next frame

        // Coloring rules in effect (compiled from settings.colorRules or the defaults) and the editor window
        CompiledColorRules colors;
        bool showColorRules = false;
        bool colorRulesWereOpen = false;        // editor window state: to detect "just opened"
        std::vector<ColorRule> colorRuleEdit;   // working copy while the editor is open

        // Display filter and packet list presentation
        FilterState filter;
        FindState find;
        StatsState stats;
        FollowState follow;
        PreferencesState preferences;
        ExportState exportDialog;
        DecodeAsState decodeAs;
        LiveState live;
        bool quitRequested = false;         // the main loop ends (set once nothing unsaved is left to ask about)
        std::shared_ptr<const dissect::Registry> registry;   // dissectors with the Decode As rules; null = the built-in ones
        double captureStartEpoch = 0;       // UTC epoch seconds of the first packet
        core::CaptureInfo captureInfo;      // file level metadata of the open capture
        core::SessionTables sessions;       // dynamic protocol session tables
        // The user's TLS keys (settings.tlsKeyLogFile, read by setTlsKeyLogFile). Owned by the UI thread: a load takes a copy
        // when it starts, so replacing the keys never races with the load pass or with detail building, which only see
        // the copy inside their own session tables.
        tls::KeyStore tlsKeys;
        std::string tlsKeyStatus;           // what the last read of the key log file found, or why it failed
        bool tlsKeyStatusIsError = false;
        bool showCaptureInfo = false;       // the Capture File Properties window
        bool orderDirty = true;             // `order` must be rebuilt (new capture or new filter)
        std::vector<uint32_t> order;        // displayed order: indices into `packets` (rebuilt by the list)
        bool scrollToSelection = false;      // bring the selected row into view (keyboard navigation)

        // Preferences, persisted to `settingsPath` when `settingsDirty` is set (see saveSettingsIfDirty)
        Settings settings;
        std::string settingsPath;   // empty = do not persist
        bool settingsDirty = false;

        // Layout
        float listHeight = 300.0f;                       // height of the packet list (user-adjustable splitter)

        /// The MAC addresses of every Ethernet frame (recorded while the capture was dissected): of the running capture, else of the loaded one.
        const packet::EthernetAddressTable *ethernetAddresses() const {
            return live.processor ? &live.processor->sessions().ethernetAddresses() : &sessions.ethernetAddresses();
        }

        /// The AH/ESP headers of every IPsec packet (recorded while the capture was dissected), same source as the addresses above.
        const packet::IpsecTable *ipsecHeaders() const {
            return live.processor ? &live.processor->sessions().ipsecHeaders() : &sessions.ipsecHeaders();
        }

        size_t displayedCount() const { return filter.active ? filter.visible.size() : packets.size(); }

        bool hasSelection() const { return selectionStart >= 0 && selectionEnd >= selectionStart; }
        bool isSelected(int byte) const { return hasSelection() && byte >= selectionStart && byte <= selectionEnd; }

        const packet::PacketInfo *currentPacket() const {
            return selectedPacket >= 0 && selectedPacket < static_cast<int>(packets.size()) ? &packets[selectedPacket]
                                                                                            : nullptr;
        }

        void clearSelection() {
            selectedPacket = -1;
            detailIndex = -1;
            detailOk = false;
            detail = packet::PacketInfo();
            selectedField = nullptr;
            selectionStart = selectionEnd = -1;
            revealSelectedField = false;
            scrollToSelection = false;
        }

        /// Selects a packet (no-op if it is already selected) and resets the field/byte selection.
        void selectPacket(int index) {
            if (index == selectedPacket) return;
            selectedPacket = index;
            selectedField = nullptr;
            selectionStart = selectionEnd = -1;
        }
    };
} // namespace ui
