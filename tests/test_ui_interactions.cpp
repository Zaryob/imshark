// Drives the real ImGui widgets headless with synthetic mouse and key events: menu bar, right-click context menus,
// file drops and the export dialog. Items are found by hovering (the hovered id is compared with the id of the label),
// so the tests click where the user would click instead of calling the handlers directly.
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <imgui.h>
#include <imgui_internal.h>

#include <ImGuiFileDialog.h>

#include <capture/live_capture.h>
#include <core.h>
#include <ui/clipboard.h>
#include <ui/time_format.h>
#include <ui/ui.h>

#include "support.h"

namespace {
    std::string g_clipboard;

    /// A directory of its own per test (the tests run in parallel processes), removed with the object.
    class TempDir {
    public:
        explicit TempDir(const std::string &name) : path_(support::tempPath(name)) { std::filesystem::create_directories(path_); }
        ~TempDir() {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
        TempDir(const TempDir &) = delete;
        TempDir &operator=(const TempDir &) = delete;

        std::string file(const std::string &name) const { return (path_ / name).string(); }
        std::string copyOfSample(const std::string &name) const {
            std::filesystem::copy_file(IMSHARK_TEST_DATA_DIR "/sample.pcap", path_ / name);
            return file(name);
        }

    private:
        std::filesystem::path path_;
    };

    class UiInteract : public ::testing::Test {
    protected:
        void SetUp() override {
            IMGUI_CHECKVERSION();
            ctx = ImGui::CreateContext();
            ImGuiIO &io = ImGui::GetIO();
            io.IniFilename = nullptr;
            io.DisplaySize = ImVec2(1280, 720);
            io.ConfigMacOSXBehaviors = false;            // Ctrl, not Cmd, on every platform
            io.ConfigInputTrickleEventQueue = false;   // a position and a button change in one frame are both seen
            unsigned char *pixels;
            int w, h;
            io.Fonts->GetTexDataAsRGBA32(&pixels, &w, &h);
            g_clipboard.clear();
            ImGuiPlatformIO &platform = ImGui::GetPlatformIO();
            platform.Platform_SetClipboardTextFn = [](ImGuiContext *, const char *text) { g_clipboard = text; };
            platform.Platform_GetClipboardTextFn = [](ImGuiContext *) -> const char * { return g_clipboard.c_str(); };
        }

        void TearDown() override {
            ImGuiFileDialog::Instance()->Close();
            ImGui::DestroyContext(ctx);
        }

        ImTextureRef logoRef{};

        void frame(ui::AppState &state, std::string *log = nullptr) {
            ImGui::GetIO().DeltaTime = 1.0f / 60.0f;
            ImGui::NewFrame();
            ui::pollLoad(state);
            ui::pollCapture(state);
            ui::drawMenuAndDialogs(state);
            ui::drawMainWindow(state, logoRef);
            if (log) ImGui::LogToBuffer();
            ui::drawStatusBar(state);
            ui::drawLoadErrorPopup(state);
            ui::drawLoadProgressPopup(state);
            if (log) {
                *log = ImGui::GetCurrentContext()->LogBuffer.c_str();
                ImGui::LogFinish();
            }
            ImGui::Render();
        }

        void frames(ui::AppState &state, int n = 3) {
            for (int i = 0; i < n; ++i) frame(state);
        }

        void load(ui::AppState &state) {
            ui::loadCapture(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
            frames(state);
        }

        /// Frames until the background load ended.
        void pumpLoad(ui::AppState &state) {
            for (int i = 0; i < 3000 && state.loading(); ++i) {
                frame(state);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            ASSERT_FALSE(state.loading());
            frames(state);
        }

        /// Frames until the background export ended (the result popup is drawn by the same frames).
        void pumpExport(ui::AppState &state) {
            for (int i = 0; i < 3000 && state.exportDialog.job; ++i) {
                frame(state);
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            ASSERT_FALSE(static_cast<bool>(state.exportDialog.job));
            frames(state);
        }

        // ---- synthetic input -------------------------------------------------------------------------------

        void moveTo(ui::AppState &state, ImVec2 p) {
            ImGui::GetIO().AddMousePosEvent(p.x, p.y);
            frame(state);
        }

        void click(ui::AppState &state, ImVec2 p, ImGuiMouseButton button = ImGuiMouseButton_Left) {
            moveTo(state, p);
            ImGui::GetIO().AddMouseButtonEvent(button, true);
            frame(state);
            ImGui::GetIO().AddMouseButtonEvent(button, false);
            frame(state);
            frames(state, 2);                  // popups opened by the click become interactive a frame later
        }

        void key(ui::AppState &state, ImGuiKey k, bool ctrl = false) {
            ImGuiIO &io = ImGui::GetIO();
            if (ctrl) io.AddKeyEvent(ImGuiMod_Ctrl, true);
            io.AddKeyEvent(k, true);
            frame(state);
            io.AddKeyEvent(k, false);
            if (ctrl) io.AddKeyEvent(ImGuiMod_Ctrl, false);
            frames(state, 2);
        }

        // ---- finding things on screen ----------------------------------------------------------------------

        static ImGuiWindow *windowNamed(const char *part) {
            for (ImGuiWindow *w: ImGui::GetCurrentContext()->Windows) {
                if (w->WasActive && std::strstr(w->Name, part)) return w;
            }
            return nullptr;
        }

        static ImGuiWindow *topPopup() {
            ImGuiContext &g = *ImGui::GetCurrentContext();
            return g.OpenPopupStack.Size ? g.OpenPopupStack.back().Window : nullptr;
        }

        static bool popupOpen(const char *name) {
            for (const ImGuiPopupData &p: ImGui::GetCurrentContext()->OpenPopupStack) {
                if (p.Window && std::strcmp(p.Window->Name, name) == 0) return true;
            }
            return false;
        }

        /// The id of `last` as ImGui computes it between PushID calls with each of `pushes` (the window's id stack is
        /// restored; ids are hashes of the stack, so they can be recomputed after the frame).
        static ImGuiID idWithin(ImGuiWindow *w, std::initializer_list<const char *> pushes, const char *last) {
            const int depth = w->IDStack.Size;
            for (const char *p: pushes) w->IDStack.push_back(w->GetID(p));
            const ImGuiID id = w->GetID(last);
            w->IDStack.resize(depth);
            return id;
        }

        /// Every id the item `label` may have: a plain item (MenuItem, Button), a submenu (BeginMenu draws an empty
        /// Selectable inside PushID(label)), a menu of the menu bar (the same inside PushID("##MenuBar")), or an
        /// item drawn between PushID(`pushed`) and PopID().
        static std::vector<ImGuiID> itemIds(ImGuiWindow *w, const char *label, const char *pushed) {
            std::vector<ImGuiID> ids = {w->GetID(label), idWithin(w, {label}, ""), idWithin(w, {"##MenuBar", label}, "")};
            if (pushed) ids.push_back(idWithin(w, {pushed}, label));
            return ids;
        }

        /// Hovers along the window (a row of items: across, a column: down) until the item `label` is the hovered one.
        bool locate(ui::AppState &state, ImGuiWindow *w, const char *label, ImVec2 &out, const char *pushed = nullptr) {
            if (!w) return false;
            const std::vector<ImGuiID> ids = itemIds(w, label, pushed);
            const ImRect r = w->Rect();
            const bool row = (w->Flags & ImGuiWindowFlags_MenuBar) != 0;      // the menu bar: items side by side
            const ImVec2 mid = r.GetCenter();
            const float from = row ? r.Min.x + 2 : r.Min.y + 2, to = row ? r.Max.x : r.Max.y;
            for (float v = from; v < to; v += 3.0f) {
                // a column of menu entries spans the width; a dialog may hold several buttons side by side
                const float xs[] = {r.Min.x + w->WindowPadding.x + 6, r.Min.x + r.GetWidth() * 0.5f, r.Min.x + r.GetWidth() * 0.8f};
                for (int k = 0; k < (row ? 1 : 3); ++k) {
                    const ImVec2 p = row ? ImVec2(v, mid.y) : ImVec2(xs[k], v);
                    moveTo(state, p);
                    const ImGuiID hovered = ImGui::GetCurrentContext()->HoveredId;
                    if (hovered != 0 && std::find(ids.begin(), ids.end(), hovered) != ids.end()) {
                        out = p;
                        return true;
                    }
                }
            }
            return false;
        }

        /// Finds a button / row of the main window by hovering: a row of items (the toolbar) is swept across at the height
        /// of its first line; the centred welcome panel is swept down at a few x positions around the window centre.
        bool locateInMain(ui::AppState &state, const char *label, ImVec2 &out, bool toolbarRow, const char *pushed = nullptr) {
            ImGuiWindow *w = windowNamed("ImShark");
            if (!w) return false;
            const std::vector<ImGuiID> ids = itemIds(w, label, pushed);
            auto hit = [&](ImVec2 p) {
                moveTo(state, p);
                const ImGuiID hovered = ImGui::GetCurrentContext()->HoveredId;
                if (hovered != 0 && std::find(ids.begin(), ids.end(), hovered) != ids.end()) {
                    out = p;
                    return true;
                }
                return false;
            };
            const ImRect r = w->Rect();
            if (toolbarRow) {
                const float y = r.Min.y + w->WindowPadding.y + ImGui::GetFrameHeight() * 0.5f;
                for (float x = r.Min.x + 2; x < r.Max.x; x += 3.0f) if (hit(ImVec2(x, y))) return true;
                return false;
            }
            const float cx = r.GetCenter().x;
            for (float y = r.Min.y + 2; y < r.Max.y; y += 3.0f) {
                for (float dx: {-120.0f, 20.0f}) if (hit(ImVec2(cx + dx, y))) return true;
            }
            return false;
        }

        bool clickInMain(ui::AppState &state, const char *label, bool toolbarRow, const char *pushed = nullptr) {
            ImVec2 p;
            if (!locateInMain(state, label, p, toolbarRow, pushed)) return false;
            click(state, p);
            return true;
        }

        bool clickInTopPopup(ui::AppState &state, const char *label, const char *pushed = nullptr) {
            ImVec2 p;
            if (!locate(state, topPopup(), label, p, pushed)) return false;
            click(state, p);
            return true;
        }

        /// Clicks through menu bar > menu > submenu ... > item.
        bool clickMenu(ui::AppState &state, std::initializer_list<const char *> path) {
            bool first = true;
            for (const char *label: path) {
                ImVec2 p;
                if (first) {
                    if (!locate(state, ImGui::FindWindowByName("##MainMenuBar"), label, p)) return false;
                    click(state, p);
                } else if (!clickInTopPopup(state, label)) {
                    return false;
                }
                first = false;
            }
            return true;
        }

        /// Centers (y) of the clickable rows of a scrolling child window, top to bottom.
        std::vector<ImVec2> rowCenters(ui::AppState &state, ImGuiWindow *w, float indent = 10) {
            std::vector<ImVec2> out;
            if (!w) return out;
            const ImRect r = w->InnerRect;
            const float x = r.Min.x + indent;
            ImGuiID previous = 0;
            float start = 0, last = 0;
            for (float y = r.Min.y + 1; y < r.Max.y; y += 3.0f) {
                moveTo(state, ImVec2(x, y));
                const ImGuiID id = ImGui::GetCurrentContext()->HoveredId;
                if (id != previous) {
                    if (previous != 0) out.push_back(ImVec2(x, (start + last) / 2));
                    start = y;
                    previous = id;
                }
                last = y;
            }
            if (previous != 0) out.push_back(ImVec2(x, (start + last) / 2));
            return out;
        }

        /// The packet rows of the list in displayed order (the column header is not one of them).
        std::vector<ImVec2> listRows(ui::AppState &state) {
            auto rows = rowCenters(state, windowNamed("Packet List"));
            if (rows.size() == state.order.size() + 1) rows.erase(rows.begin());
            return rows;
        }

        void closePopups(ui::AppState &state) {
            key(state, ImGuiKey_Escape);
            ImGuiContext &g = *ImGui::GetCurrentContext();
            for (int i = 0; i < 4 && g.OpenPopupStack.Size; ++i) key(state, ImGuiKey_Escape);
        }

        ImGuiContext *ctx = nullptr;
    };

    std::string readText(const std::string &path) {
        std::ifstream in(path, std::ios::binary);
        std::ostringstream text;
        text << in.rdbuf();
        return text.str();
    }

    size_t countOf(const std::string &text, const std::string &needle) {
        size_t n = 0;
        for (size_t at = text.find(needle); at != std::string::npos; at = text.find(needle, at + needle.size())) ++n;
        return n;
    }

    /// Number of packets/rows an export file holds, read back the way a user would open it.
    size_t packetsIn(const std::string &path, exporter::Format format) {
        if (format == exporter::Format::Csv) return countOf(readText(path), "\n") - 1;       // minus the header line
        if (format == exporter::Format::Json) return countOf(readText(path), "\"number\":");
        ui::AppState check;
        ui::loadCapture(check, path);
        return check.loadFailed ? 0 : check.packets.size();
    }
} // namespace

// ---- menu bar -----------------------------------------------------------------------------------------------

TEST_F(UiInteract, FileOpenMenuItemOpensTheFileDialog) {
    ui::AppState state;
    frames(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Open..."}));
    EXPECT_TRUE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
}

TEST_F(UiInteract, CtrlOOpensTheFileDialog) {
    ui::AppState state;
    frames(state);
    EXPECT_FALSE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
    key(state, ImGuiKey_O, true);
    EXPECT_TRUE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
}

TEST_F(UiInteract, CaptureFileDialogHasAUsableSizeOnItsFirstFrame) {
    ui::AppState state;
    ui::openCaptureDialog();
    frame(state);
    ImGuiWindow *dialog = ImGui::FindWindowByName("Open capture file##ChooseFileDlgKey");
    ASSERT_NE(dialog, nullptr);
    EXPECT_TRUE(dialog->Active);
    EXPECT_GE(dialog->Size.x, 640.0f);
    EXPECT_GE(dialog->Size.y, 420.0f);
    EXPECT_NEAR(dialog->Pos.x + dialog->Size.x * 0.5f, 640.0f, 1.0f);
    EXPECT_NEAR(dialog->Pos.y + dialog->Size.y * 0.5f, 360.0f, 20.0f); // the menu bar reduces the work area

    // User resizing remains effective while the dialog is open.
    ImGui::SetWindowSize(dialog->Name, ImVec2(700, 460));
    frames(state);
    EXPECT_FLOAT_EQ(dialog->Size.x, 700.0f);
    EXPECT_FLOAT_EQ(dialog->Size.y, 460.0f);
}

TEST_F(UiInteract, CaptureFileDialogFitsASmallViewportOnItsFirstFrame) {
    ui::AppState state;
    ImGui::GetIO().DisplaySize = ImVec2(640, 400);
    ui::openCaptureDialog();
    frame(state);
    ImGuiWindow *dialog = ImGui::FindWindowByName("Open capture file##ChooseFileDlgKey");
    ASSERT_NE(dialog, nullptr);
    EXPECT_GE(dialog->Size.x, 600.0f);
    EXPECT_GE(dialog->Size.y, 340.0f);
    EXPECT_GE(dialog->Pos.x, 0.0f);
    EXPECT_GE(dialog->Pos.y, 0.0f);
    EXPECT_LE(dialog->Pos.x + dialog->Size.x, 640.0f);
    EXPECT_LE(dialog->Pos.y + dialog->Size.y, 400.0f);
}

TEST_F(UiInteract, OpenRecentMenuLoadsTheChosenCapture) {
    ui::AppState state;
    TempDir dir("recent");
    const std::string recent = dir.copyOfSample("recent.pcap");
    state.settings.recentFiles = {recent};
    frames(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Open Recent"}));
    ASSERT_TRUE(clickInTopPopup(state, "recent.pcap", recent.c_str()));
    pumpLoad(state);
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_EQ(state.displayName, recent);
}

TEST_F(UiInteract, ClearRecentEmptiesTheRecentList) {
    ui::AppState state;
    state.settings.recentFiles = {"/some/where/a.pcap", "/some/where/b.pcap"};
    frames(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Open Recent", "Clear Recent"}));
    EXPECT_TRUE(state.settings.recentFiles.empty());
    EXPECT_TRUE(state.settingsDirty);
}

TEST_F(UiInteract, FileExportMenuItemOpensTheExportOptions) {
    ui::AppState state;
    load(state);
    EXPECT_FALSE(popupOpen("Export Packets"));
    ASSERT_TRUE(clickMenu(state, {"File", "Export Packets..."}));
    EXPECT_TRUE(popupOpen("Export Packets"));
}

TEST_F(UiInteract, FileCloseMenuItemClosesTheCapture) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Close File"}));
    frames(state);
    EXPECT_TRUE(state.packets.empty());
    EXPECT_TRUE(state.currentFile.empty());
    EXPECT_EQ(state.selectedPacket, -1);
}

TEST_F(UiInteract, CtrlWClosesTheCapture) {
    ui::AppState state;
    load(state);
    key(state, ImGuiKey_W, true);
    EXPECT_TRUE(state.packets.empty());
    EXPECT_TRUE(state.currentFile.empty());
}

TEST_F(UiInteract, FilePropertiesMenuItemOpensTheCaptureInfoWindow) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Capture File Properties..."}));
    EXPECT_TRUE(state.showCaptureInfo);
    frames(state);
    EXPECT_NE(windowNamed("Capture File Properties"), nullptr);
}

TEST_F(UiInteract, ExitMenuItemEndsTheMainLoop) {
    ui::AppState state;
    frames(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Exit"}));
    EXPECT_TRUE(state.quitRequested);
}

TEST_F(UiInteract, StatisticsMenuItemsToggleTheirWindows) {
    struct Item {
        const char *label;
        bool ui::StatsState::*flag;
    };
    const Item items[] = {{"Expert Information", &ui::StatsState::showExpert},
                          {"Protocol Hierarchy", &ui::StatsState::showHierarchy},
                          {"Conversations", &ui::StatsState::showConversations},
                          {"Endpoints", &ui::StatsState::showEndpoints}};
    ui::AppState state;
    load(state);
    for (const Item &item: items) {
        SCOPED_TRACE(item.label);
        ASSERT_TRUE(clickMenu(state, {"Statistics", item.label}));
        EXPECT_TRUE(state.stats.*item.flag);
        EXPECT_NE(windowNamed(item.label), nullptr) << "the window is drawn";
        ASSERT_TRUE(clickMenu(state, {"Statistics", item.label}));
        EXPECT_FALSE(state.stats.*item.flag) << "a second click hides it again";
        frames(state);
        EXPECT_EQ(windowNamed(item.label), nullptr);
    }
}

TEST_F(UiInteract, ViewMenuSwitchesTheTheme) {
    ui::AppState state;
    frames(state);
    ASSERT_TRUE(state.settings.darkTheme);
    ASSERT_TRUE(clickMenu(state, {"View", "Light Theme"}));
    EXPECT_FALSE(state.settings.darkTheme);
    EXPECT_TRUE(state.settingsDirty);
    ASSERT_TRUE(clickMenu(state, {"View", "Dark Theme"}));
    EXPECT_TRUE(state.settings.darkTheme);
}

TEST_F(UiInteract, ViewMenuChangesTheTimeFormatAndColorizing) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickMenu(state, {"View", "Time Display Format", ui::timeFormatName(ui::TimeFormat::UtcDateTime)}));
    EXPECT_EQ(state.settings.timeFormat, ui::TimeFormat::UtcDateTime);

    const bool colorize = state.settings.colorize;
    ASSERT_TRUE(clickMenu(state, {"View", "Colorize Packet List"}));
    EXPECT_NE(state.settings.colorize, colorize);
    frames(state);
}

TEST_F(UiInteract, ViewMenuOpensTheColoringRulesEditor) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickMenu(state, {"View", "Coloring Rules..."}));
    EXPECT_TRUE(state.showColorRules);
    frames(state);
    EXPECT_NE(windowNamed("Coloring Rules"), nullptr);
}

TEST_F(UiInteract, EditAndAnalyzeMenusOpenTheirWindows) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickMenu(state, {"Edit", "Preferences..."}));
    EXPECT_TRUE(state.preferences.open);
    ASSERT_TRUE(clickMenu(state, {"Analyze", "Decode As..."}));
    EXPECT_TRUE(state.decodeAs.open);
    frames(state);
    EXPECT_NE(windowNamed("Preferences"), nullptr);
    EXPECT_NE(windowNamed("Decode As"), nullptr);
}

TEST_F(UiInteract, AnalyzeMenuFollowsTheStreamOfTheSelectedPacket) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 9;                 // the HTTP request
    frames(state);
    ASSERT_TRUE(clickMenu(state, {"Analyze", "Follow TCP Stream"}));
    EXPECT_TRUE(state.follow.open);
    EXPECT_NE(state.follow.title.find("TCP"), std::string::npos);
}

TEST_F(UiInteract, AnalyzeMenuOffersNoStreamForAnArpPacket) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 0;                 // ARP
    frames(state);
    ASSERT_TRUE(clickMenu(state, {"Analyze", "Decode As..."})) << "the menu itself opens";
    EXPECT_FALSE(state.follow.open);
    state.decodeAs.open = false;
    ImVec2 p;
    ASSERT_TRUE(locate(state, ImGui::FindWindowByName("##MainMenuBar"), "Analyze", p));
    click(state, p);
    if (locate(state, topPopup(), "Follow TCP Stream", p)) click(state, p);    // greyed out: the click does nothing
    closePopups(state);
    EXPECT_FALSE(state.follow.open);
}

// ---- right-click context menus --------------------------------------------------------------------------------

TEST_F(UiInteract, PacketListContextMenuCopiesTheRowAndItsColumns) {
    ui::AppState state;
    load(state);
    const auto rows = listRows(state);
    ASSERT_EQ(rows.size(), 16u);
    const int index = 9;
    const packet::PacketInfo &packet = state.packets[index];

    struct Entry {
        const char *label;
        std::string expected;
    };
    const Entry entries[] = {{"Copy Row", ui::summaryRow(packet)},
                             {"Copy Source", packet.source},
                             {"Copy Destination", packet.destination},
                             {"Copy Info", packet.info}};
    for (const Entry &entry: entries) {
        SCOPED_TRACE(entry.label);
        g_clipboard.clear();
        click(state, rows[index], ImGuiMouseButton_Right);
        ASSERT_TRUE(topPopup() != nullptr) << "the context menu opened";
        ASSERT_TRUE(clickInTopPopup(state, entry.label));
        EXPECT_EQ(g_clipboard, entry.expected);
    }
}

TEST_F(UiInteract, PacketListContextMenuOffersFollowTcpOnlyForTcpPackets) {
    ui::AppState state;
    load(state);
    const auto rows = listRows(state);
    ASSERT_EQ(rows.size(), 16u);
    ImVec2 p;

    click(state, rows[0], ImGuiMouseButton_Right);                 // ARP
    ASSERT_TRUE(topPopup() != nullptr);
    EXPECT_TRUE(locate(state, topPopup(), "Copy Row", p));
    EXPECT_FALSE(locate(state, topPopup(), "Follow TCP Stream", p));
    EXPECT_FALSE(locate(state, topPopup(), "Follow UDP Stream", p));
    closePopups(state);

    click(state, rows[9], ImGuiMouseButton_Right);                 // TCP
    ASSERT_TRUE(topPopup() != nullptr);
    EXPECT_TRUE(locate(state, topPopup(), "Follow TCP Stream", p));
    EXPECT_FALSE(locate(state, topPopup(), "Follow UDP Stream", p));
}

TEST_F(UiInteract, PacketListContextMenuFollowsTheTcpStreamOfTheClickedRow) {
    ui::AppState state;
    load(state);
    const auto rows = listRows(state);
    ASSERT_EQ(rows.size(), 16u);
    click(state, rows[9], ImGuiMouseButton_Right);
    ASSERT_TRUE(clickInTopPopup(state, "Follow TCP Stream"));
    EXPECT_EQ(state.selectedPacket, 9) << "following selects the row";
    EXPECT_TRUE(state.follow.open);
    for (int i = 0; i < 3000 && state.follow.job; ++i) {
        frame(state);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_TRUE(state.follow.valid);
    EXPECT_EQ(state.follow.stream.packets, 5);
    EXPECT_NE(windowNamed("Follow"), nullptr);
}

TEST_F(UiInteract, PacketListContextMenuFollowsTheUdpStreamOfTheClickedRow) {
    ui::AppState state;
    load(state);
    const auto rows = listRows(state);
    ASSERT_EQ(rows.size(), 16u);
    click(state, rows[4], ImGuiMouseButton_Right);                 // DNS over UDP
    ASSERT_TRUE(clickInTopPopup(state, "Follow UDP Stream"));
    EXPECT_TRUE(state.follow.open);
    EXPECT_NE(state.follow.title.find("UDP"), std::string::npos);
}

TEST_F(UiInteract, RightClickDoesNotChangeTheSelection) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 2;
    frames(state);
    const auto rows = listRows(state);
    ASSERT_GE(rows.size(), 6u);
    click(state, rows[5], ImGuiMouseButton_Right);
    ASSERT_TRUE(topPopup() != nullptr);
    EXPECT_EQ(state.selectedPacket, 2);
}

TEST_F(UiInteract, ProtocolTreeContextMenuCopiesTheFieldInItsForms) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 6;                                       // TCP SYN with options
    frames(state);
    ASSERT_TRUE(state.detailOk);
    const auto rows = rowCenters(state, windowNamed("Packet Tree"), 40);   // inside the rows of the nested fields too
    ASSERT_GE(rows.size(), 3u);

    click(state, rows[0], ImGuiMouseButton_Right);
    ASSERT_NE(state.selectedField, nullptr) << "a right click selects the field";
    const packet::Field field = *state.selectedField;
    ASSERT_GT(field.length, 0u);
    const auto &raw = state.detail.raw_data;
    ASSERT_TRUE(topPopup() != nullptr);

    struct Entry {
        const char *label;
        std::string expected;
    };
    const Entry entries[] = {{"Copy", field.text},
                             {"Copy Value", ui::fieldValue(field)},
                             {"Copy Bytes as Hex", ui::bytesToHex(raw, field.offset, field.length)},
                             {"Copy Bytes as ASCII", ui::bytesToAscii(raw, field.offset, field.length)}};
    for (size_t i = 0; i < sizeof entries / sizeof entries[0]; ++i) {
        SCOPED_TRACE(entries[i].label);
        g_clipboard.clear();
        if (i > 0) click(state, rows[0], ImGuiMouseButton_Right);
        ASSERT_TRUE(clickInTopPopup(state, entries[i].label));
        EXPECT_EQ(g_clipboard, entries[i].expected);
    }
}

TEST_F(UiInteract, HexViewContextMenuCopiesTheSelectedBytes) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 6;
    frames(state);
    ASSERT_TRUE(state.detailOk);
    state.selectionStart = 2;
    state.selectionEnd = 5;
    frames(state);
    ImGuiWindow *hex = windowNamed("HexView");
    ASSERT_NE(hex, nullptr);
    const auto &raw = state.detail.raw_data;

    struct Entry {
        const char *label;
        std::string expected;
    };
    const Entry entries[] = {{"Copy Selection as Hex", ui::bytesToHex(raw, 2, 4)},
                             {"Copy Selection as ASCII", ui::bytesToAscii(raw, 2, 4)},
                             {"Copy All as Hex Dump", ui::hexDump(raw)}};
    for (const Entry &entry: entries) {
        SCOPED_TRACE(entry.label);
        g_clipboard.clear();
        click(state, hex->InnerRect.GetCenter(), ImGuiMouseButton_Right);
        ASSERT_TRUE(topPopup() != nullptr);
        ASSERT_TRUE(clickInTopPopup(state, entry.label));
        EXPECT_EQ(g_clipboard, entry.expected);
    }
}

// ---- dropping files on the window -----------------------------------------------------------------------------

TEST_F(UiInteract, DroppedCaptureFileIsOpened) {
    ui::AppState state;
    TempDir dir("drop");
    const std::string path = dir.copyOfSample("dropped.pcap");
    const char *paths[] = {path.c_str()};
    frames(state);
    ui::openDroppedFiles(state, 1, paths);
    pumpLoad(state);
    EXPECT_FALSE(state.loadFailed);
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_EQ(state.displayName, path);
    ASSERT_FALSE(state.settings.recentFiles.empty());
    EXPECT_EQ(state.settings.recentFiles.front(), path) << "a dropped file is remembered like an opened one";
}

TEST_F(UiInteract, DroppedCaptureReplacesTheOpenCaptureAndResetsTheSelection) {
    ui::AppState state;
    TempDir dir("replace");
    const std::string path = dir.copyOfSample("second.pcap");
    load(state);
    state.selectedPacket = 3;
    frames(state);
    const char *paths[] = {path.c_str()};
    ui::openDroppedFiles(state, 1, paths);
    pumpLoad(state);
    EXPECT_EQ(state.displayName, path);
    EXPECT_EQ(state.selectedPacket, -1);
}

TEST_F(UiInteract, OnlyTheFirstOfSeveralDroppedFilesIsOpened) {
    ui::AppState state;
    TempDir dir("several");
    const std::string first = dir.copyOfSample("first.pcap");
    const std::string second = dir.file("second.pcap");
    const char *paths[] = {first.c_str(), second.c_str()};
    ui::openDroppedFiles(state, 2, paths);
    pumpLoad(state);
    EXPECT_FALSE(state.loadFailed);
    EXPECT_EQ(state.displayName, first);
}

TEST_F(UiInteract, EmptyDropChangesNothing) {
    ui::AppState state;
    load(state);
    ui::openDroppedFiles(state, 0, nullptr);
    EXPECT_FALSE(state.loading());
    EXPECT_EQ(state.packets.size(), 16u);
}

TEST_F(UiInteract, DroppedGzippedCaptureIsOpened) {
    ui::AppState state;
    TempDir dir("gz");
    const std::string path = dir.file("dropped.pcap.gz");
    std::filesystem::copy_file(IMSHARK_TEST_DATA_DIR "/sample.pcap.gz", path);
    const char *paths[] = {path.c_str()};
    ui::openDroppedFiles(state, 1, paths);
    pumpLoad(state);
    EXPECT_FALSE(state.loadFailed) << state.loadMessage;
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_EQ(state.displayName, path);
}

TEST_F(UiInteract, DroppedMissingFileReportsAnErrorAndKeepsTheOpenCapture) {
    ui::AppState state;
    TempDir dir("missing");
    load(state);
    state.selectedPacket = 4;
    frames(state);
    const std::string missing = dir.file("not-there.pcap");
    const char *paths[] = {missing.c_str()};
    ui::openDroppedFiles(state, 1, paths);
    pumpLoad(state);
    EXPECT_TRUE(state.loadFailed);
    EXPECT_FALSE(state.loadMessage.empty());
    EXPECT_TRUE(popupOpen("Load problem")) << "the error popup is shown";
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_EQ(state.selectedPacket, 4);
    EXPECT_EQ(support::nativePath(state.currentFile), support::nativePath(IMSHARK_TEST_DATA_DIR "/sample.pcap"));
}

TEST_F(UiInteract, DroppedNonCaptureFileReportsAnErrorAndKeepsTheOpenCapture) {
    ui::AppState state;
    TempDir dir("text");
    load(state);
    const std::string path = dir.file("notes.txt");
    std::ofstream(path) << "this is not a packet capture, just some text for the reader to reject\n";
    const char *paths[] = {path.c_str()};
    ui::openDroppedFiles(state, 1, paths);
    pumpLoad(state);
    EXPECT_TRUE(state.loadFailed);
    EXPECT_TRUE(popupOpen("Load problem"));
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_EQ(support::nativePath(state.currentFile), support::nativePath(IMSHARK_TEST_DATA_DIR "/sample.pcap"));
}

TEST_F(UiInteract, DroppedDirectoryReportsAnErrorAndKeepsTheOpenCapture) {
    ui::AppState state;
    TempDir dir("folder");
    load(state);
    const std::string path = dir.file("");
    const char *paths[] = {path.c_str()};
    ui::openDroppedFiles(state, 1, paths);
    pumpLoad(state);
    EXPECT_TRUE(state.loadFailed);
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_EQ(support::nativePath(state.currentFile), support::nativePath(IMSHARK_TEST_DATA_DIR "/sample.pcap"));
}

TEST_F(UiInteract, DroppedFileDuringAnUnsavedLiveCaptureAsksFirst) {
    ui::AppState state;
    TempDir dir("live");
    const std::string path = dir.copyOfSample("dropped.pcap");
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    ASSERT_TRUE(state.live.device->injectPacket(1700000000, 0, support::hex(support::kArpRequest)));
    ASSERT_TRUE(state.live.device->injectPacket(1700000001, 0, support::hex(support::kEthIpUdp)));
    frames(state);
    ASSERT_EQ(state.packets.size(), 2u);

    const char *paths[] = {path.c_str()};
    ui::openDroppedFiles(state, 1, paths);
    EXPECT_FALSE(state.loading()) << "nothing is replaced before the answer";
    EXPECT_EQ(state.live.pending.kind, ui::PendingAction::Open);
    EXPECT_EQ(state.live.pending.path, path);
    frames(state);
    EXPECT_TRUE(popupOpen("Unsaved capture")) << "the question is shown";

    ui::resolveUnsaved(state, ui::UnsavedChoice::Cancel);
    EXPECT_TRUE(state.live.capturing());
    EXPECT_EQ(state.packets.size(), 2u);

    ui::openDroppedFiles(state, 1, paths);
    ui::resolveUnsaved(state, ui::UnsavedChoice::Discard);
    pumpLoad(state);
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_FALSE(state.live.session);
}

// ---- export ---------------------------------------------------------------------------------------------------

namespace {
    constexpr exporter::Format kAllFormats[] = {exporter::Format::Pcap, exporter::Format::Pcapng, exporter::Format::Csv, exporter::Format::Json};
}

TEST_F(UiInteract, ExportOfAllPacketsWritesEveryPacketInEveryFormat) {
    ui::AppState state;
    TempDir dir("export_all");
    load(state);
    ASSERT_TRUE(ui::applyFilterNow(state, "tcp")) << "a filter does not limit an export of all packets";
    for (const auto format: kAllFormats) {
        SCOPED_TRACE(exporter::formatName(format));
        const std::string path = dir.file(std::string("all") + exporter::formatExtension(format));
        ASSERT_TRUE(ui::startExport(state, ui::ExportState::All, format, path));
        pumpExport(state);
        ASSERT_FALSE(state.exportDialog.resultIsError) << state.exportDialog.resultMessage;
        EXPECT_NE(state.exportDialog.resultMessage.find("Exported 16 packets"), std::string::npos) << state.exportDialog.resultMessage;
        EXPECT_EQ(packetsIn(path, format), 16u);
    }
}

TEST_F(UiInteract, ExportOfDisplayedPacketsWritesOnlyTheFilteredPackets) {
    ui::AppState state;
    TempDir dir("export_displayed");
    load(state);
    ASSERT_TRUE(ui::applyFilterNow(state, "tcp"));
    frames(state);
    for (const auto format: kAllFormats) {
        SCOPED_TRACE(exporter::formatName(format));
        const std::string path = dir.file(std::string("displayed") + exporter::formatExtension(format));
        ASSERT_TRUE(ui::startExport(state, ui::ExportState::Displayed, format, path));
        pumpExport(state);
        ASSERT_FALSE(state.exportDialog.resultIsError) << state.exportDialog.resultMessage;
        EXPECT_EQ(packetsIn(path, format), 7u);
    }
}

TEST_F(UiInteract, ExportOfTheSelectedPacketWritesThatPacketInEveryFormat) {
    ui::AppState state;
    TempDir dir("export_selected");
    load(state);
    state.selectedPacket = 9;
    frames(state);
    for (const auto format: kAllFormats) {
        SCOPED_TRACE(exporter::formatName(format));
        const std::string path = dir.file(std::string("selected") + exporter::formatExtension(format));
        ASSERT_TRUE(ui::startExport(state, ui::ExportState::Selected, format, path));
        pumpExport(state);
        ASSERT_FALSE(state.exportDialog.resultIsError) << state.exportDialog.resultMessage;
        EXPECT_EQ(packetsIn(path, format), 1u);
    }
}

TEST_F(UiInteract, ExportedCaptureFileKeepsTheOriginalFrames) {
    ui::AppState state;
    TempDir dir("export_frames");
    load(state);
    ASSERT_TRUE(ui::applyFilterNow(state, "dns"));
    frames(state);
    for (const auto format: {exporter::Format::Pcap, exporter::Format::Pcapng}) {
        SCOPED_TRACE(exporter::formatName(format));
        const std::string path = dir.file(std::string("dns") + exporter::formatExtension(format));
        ASSERT_TRUE(ui::startExport(state, ui::ExportState::Displayed, format, path));
        pumpExport(state);
        ui::AppState check;
        ui::loadCapture(check, path);
        ASSERT_EQ(check.packets.size(), state.filter.visible.size());
        for (size_t i = 0; i < check.packets.size(); ++i) {
            EXPECT_EQ(check.packets[i].info, state.packets[state.filter.visible[i]].info);
            EXPECT_EQ(check.packets[i].frame_length, state.packets[state.filter.visible[i]].frame_length);
        }
    }
}

TEST_F(UiInteract, ExportedTableFollowsTheDisplayedOrder) {
    ui::AppState state;
    TempDir dir("export_order");
    load(state);
    frames(state);
    ASSERT_EQ(state.order.size(), 16u);
    std::reverse(state.order.begin(), state.order.end());        // as if the list were sorted by No. descending
    const std::string path = dir.file("sorted.csv");
    ASSERT_TRUE(ui::startExport(state, ui::ExportState::Displayed, exporter::Format::Csv, path));
    pumpExport(state);
    const std::string csv = readText(path);
    const size_t first = csv.find('\n') + 1;
    EXPECT_EQ(csv.compare(first, 5, "\"16\","), 0) << csv.substr(first, 40);
}

TEST_F(UiInteract, ExportingOverTheOpenCaptureIsRefusedAndLeavesItIntact) {
    ui::AppState state;
    TempDir dir("export_over");
    const std::string path = dir.copyOfSample("open.pcap");
    ui::loadCapture(state, path);
    frames(state);
    ASSERT_TRUE(ui::startExport(state, ui::ExportState::All, exporter::Format::Pcap, path));
    pumpExport(state);
    EXPECT_TRUE(state.exportDialog.resultIsError);
    EXPECT_NE(state.exportDialog.resultMessage.find("open capture"), std::string::npos) << state.exportDialog.resultMessage;
    EXPECT_TRUE(popupOpen("Export finished")) << "the error is shown";
    EXPECT_EQ(packetsIn(path, exporter::Format::Pcap), 16u);
}

TEST_F(UiInteract, ExportRefusesAnEmptySelectionAndAnEmptyPath) {
    ui::AppState state;
    TempDir dir("export_none");
    load(state);
    EXPECT_FALSE(ui::startExport(state, ui::ExportState::Selected, exporter::Format::Csv, dir.file("none.csv")));
    EXPECT_FALSE(ui::startExport(state, ui::ExportState::All, exporter::Format::Csv, ""));
    EXPECT_FALSE(std::filesystem::exists(dir.file("none.csv")));
}

TEST_F(UiInteract, ExportSuccessIsAnnouncedInAPopup) {
    ui::AppState state;
    TempDir dir("export_popup");
    load(state);
    const std::string path = dir.file("popup.json");
    ASSERT_TRUE(ui::startExport(state, ui::ExportState::All, exporter::Format::Json, path));
    pumpExport(state);
    EXPECT_FALSE(state.exportDialog.resultIsError);
    EXPECT_TRUE(popupOpen("Export finished"));
    EXPECT_NE(state.exportDialog.resultMessage.find(path), std::string::npos);
}

TEST_F(UiInteract, ExportDialogCancelButtonClosesItWithoutExporting) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Export Packets..."}));
    ASSERT_TRUE(popupOpen("Export Packets"));
    ASSERT_TRUE(clickInTopPopup(state, "Cancel"));
    EXPECT_FALSE(popupOpen("Export Packets"));
    EXPECT_FALSE(ImGuiFileDialog::Instance()->IsOpened("ExportDlgKey"));
    EXPECT_FALSE(static_cast<bool>(state.exportDialog.job));
}

TEST_F(UiInteract, ExportDialogSaveAsOpensTheFileChooser) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickMenu(state, {"File", "Export Packets..."}));
    ASSERT_TRUE(popupOpen("Export Packets"));
    ASSERT_TRUE(clickInTopPopup(state, "Save As..."));
    EXPECT_TRUE(ImGuiFileDialog::Instance()->IsOpened("ExportDlgKey"));
    EXPECT_FALSE(popupOpen("Export Packets")) << "the options popup makes room for the chooser";
}

TEST_F(UiInteract, ExportDialogDoesNotOfferSaveForAnEmptySelection) {
    ui::AppState state;
    load(state);
    state.exportDialog.range = ui::ExportState::Selected;       // nothing is selected
    ASSERT_TRUE(clickMenu(state, {"File", "Export Packets..."}));
    ASSERT_TRUE(popupOpen("Export Packets"));
    ImVec2 p;
    if (locate(state, topPopup(), "Save As...", p)) click(state, p);
    EXPECT_FALSE(ImGuiFileDialog::Instance()->IsOpened("ExportDlgKey"));
}

// ---- welcome panel, toolbar and status bar ----------------------------------------------------------------------

TEST_F(UiInteract, WelcomePanelIsShownOnlyWithoutACapture) {
    ui::AppState state;
    frames(state);
    EXPECT_TRUE(ui::welcomeVisible(state));
    load(state);
    EXPECT_FALSE(ui::welcomeVisible(state));
    ui::closeCapture(state);
    frames(state);
    EXPECT_TRUE(ui::welcomeVisible(state));
}

TEST_F(UiInteract, WelcomeOpenButtonOpensTheFileDialog) {
    ui::AppState state;
    frames(state);
    EXPECT_FALSE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
    ASSERT_TRUE(clickInMain(state, "Open capture...", false));
    EXPECT_TRUE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
}

TEST_F(UiInteract, WelcomeLiveCaptureButtonFollowsAvailability) {
    ui::AppState state;
    frames(state);
    ImVec2 p;
    if (!capture::liveCaptureAvailable()) {
        EXPECT_FALSE(locateInMain(state, "Start live capture...", p, false)) << "not offered in a build without live capture";
        return;
    }
    ASSERT_TRUE(clickInMain(state, "Start live capture...", false));
    EXPECT_TRUE(state.live.dialog.open) << "no interface chosen yet: the interfaces dialog opens";
}

TEST_F(UiInteract, WelcomeRecentFileClickRequestsOpen) {
    ui::AppState state;
    TempDir dir("welcome_recent");
    const std::string recent = dir.copyOfSample("welcome.pcap");
    state.settings.recentFiles = {recent};
    frames(state);
    ASSERT_TRUE(clickInMain(state, "welcome.pcap", false, recent.c_str()));
    pumpLoad(state);
    EXPECT_EQ(state.displayName, recent);
    EXPECT_EQ(state.packets.size(), 16u);
}

TEST_F(UiInteract, WelcomePanelWithLogoDrawsImageAndStaysInteractive) {
    ui::AppState state;
    logoRef = ImTextureRef(static_cast<ImTextureID>(0x42));
    frames(state);
    ImGuiWindow *mainWin = windowNamed("ImShark");
    ASSERT_NE(mainWin, nullptr);
    bool foundImage = false;
    for (const ImDrawCmd &cmd: mainWin->DrawList->CmdBuffer) {
        if (cmd.TexRef.GetTexID() == logoRef.GetTexID()) {
            foundImage = true;
            break;
        }
    }
    EXPECT_TRUE(foundImage);
    EXPECT_FALSE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
    ASSERT_TRUE(clickInMain(state, "Open capture...", false));
    EXPECT_TRUE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
}

TEST_F(UiInteract, WelcomePanelWithLogoRecentFileClickRequestsOpen) {
    ui::AppState state;
    logoRef = ImTextureRef(static_cast<ImTextureID>(0x42));
    TempDir dir("welcome_logo_recent");
    const std::string recent = dir.copyOfSample("welcome_logo.pcap");
    state.settings.recentFiles = {recent};
    frames(state);
    ASSERT_TRUE(clickInMain(state, "welcome_logo.pcap", false, recent.c_str()));
    pumpLoad(state);
    EXPECT_EQ(state.displayName, recent);
    EXPECT_EQ(state.packets.size(), 16u);
}

TEST_F(UiInteract, ToolbarEnabledStatesFollowTheCapture) {
    ui::AppState state;
    frames(state);
    ui::ToolbarEnabled e = ui::toolbarEnabled(state);
    EXPECT_TRUE(e.open);
    EXPECT_FALSE(e.close);
    EXPECT_FALSE(e.reload);
    EXPECT_FALSE(e.stop);
    EXPECT_FALSE(e.restart);
    EXPECT_FALSE(e.find);
    EXPECT_FALSE(e.statistics);
    EXPECT_EQ(e.start, capture::liveCaptureAvailable());

    load(state);
    e = ui::toolbarEnabled(state);
    EXPECT_TRUE(e.close);
    EXPECT_TRUE(e.reload);
    EXPECT_TRUE(e.find);
    EXPECT_TRUE(e.statistics);
    EXPECT_FALSE(e.restart) << "a file is not a capture session";
}

TEST_F(UiInteract, ToolbarEnabledStatesOfALiveSession) {
    ui::AppState state;
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    frames(state);
    ui::ToolbarEnabled e = ui::toolbarEnabled(state);
    EXPECT_TRUE(e.close);
    EXPECT_FALSE(e.reload) << "a live capture cannot be loaded again";
    EXPECT_FALSE(e.restart) << "an injected session has no device to restart";
    if (capture::liveCaptureAvailable()) {
        EXPECT_TRUE(e.stop);
        EXPECT_FALSE(e.start);
        ui::stopCapture(state);
        e = ui::toolbarEnabled(state);
        EXPECT_FALSE(e.stop);
        EXPECT_TRUE(e.start);
    }
}

TEST_F(UiInteract, ToolbarButtonsDoTheirJob) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(clickInMain(state, "Find", true));
    EXPECT_TRUE(state.find.open);

    ASSERT_TRUE(clickInMain(state, "Statistics", true));
    ASSERT_TRUE(clickInTopPopup(state, "Conversations"));
    EXPECT_TRUE(state.stats.showConversations);
    closePopups(state);

    ASSERT_TRUE(clickInMain(state, "Reload", true));
    pumpLoad(state);
    EXPECT_EQ(state.packets.size(), 16u);

    ASSERT_TRUE(clickInMain(state, "Close", true));
    frames(state);
    EXPECT_TRUE(state.currentFile.empty());
    EXPECT_TRUE(state.packets.empty());

    // disabled now: clicking Close, Find or Reload does nothing
    ImVec2 p;
    ASSERT_TRUE(locateInMain(state, "Find", p, true));
    state.find.open = false;
    click(state, p);
    EXPECT_FALSE(state.find.open) << "Find is disabled without packets";

    ASSERT_TRUE(clickInMain(state, "Open", true));
    EXPECT_TRUE(ImGuiFileDialog::Instance()->IsOpened("ChooseFileDlgKey"));
}

TEST_F(UiInteract, ToolbarCanBeHiddenFromTheViewMenu) {
    ui::AppState state;
    frames(state);
    ImVec2 p;
    EXPECT_TRUE(locateInMain(state, "Open", p, true));
    ASSERT_TRUE(clickMenu(state, {"View", "Toolbar"}));
    EXPECT_FALSE(state.settings.showToolbar);
    EXPECT_TRUE(state.settingsDirty);
    frames(state);
    EXPECT_FALSE(locateInMain(state, "Open", p, true));
}

TEST_F(UiInteract, StatusBarSegmentsDescribeTheCapture) {
    ui::AppState state;
    frames(state);
    ui::StatusSegments seg = ui::statusSegments(state);
    EXPECT_EQ(seg.left, "No file loaded. Use File > Open.");
    EXPECT_TRUE(seg.displayed.empty());
    EXPECT_TRUE(seg.selected.empty());

    load(state);
    seg = ui::statusSegments(state);
    EXPECT_EQ(seg.left, "sample.pcap");
    EXPECT_EQ(seg.leftTooltip, state.displayName);
    EXPECT_EQ(seg.displayed, "Displayed: 16 / 16") << "shown without a filter too";
    EXPECT_TRUE(seg.selected.empty());
    EXPECT_TRUE(seg.filter.empty());

    ASSERT_TRUE(ui::applyFilterNow(state, "tcp"));
    frames(state);
    ASSERT_FALSE(state.filter.visible.empty());
    state.selectPacket(static_cast<int>(state.filter.visible.front()));
    frames(state);
    seg = ui::statusSegments(state);
    EXPECT_EQ(seg.selected, "Selected: #" + std::to_string(state.currentPacket()->number));
    EXPECT_EQ(seg.filter, "tcp");
    EXPECT_EQ(seg.displayed, "Displayed: " + std::to_string(state.displayedCount()) + " / 16");
}

TEST_F(UiInteract, StatusBarKeepsLoadAndCaptureMessages) {
    ui::AppState state;
    state.loadMessage = "Truncated file";
    state.loadFailed = false;
    state.live.error = "no permission";
    frames(state);
    const ui::StatusSegments seg = ui::statusSegments(state);
    EXPECT_EQ(seg.message, "Truncated file");
    EXPECT_EQ(seg.error, "no permission");
}

TEST_F(UiInteract, LongStatusErrorsStaySeparateAndShowTheirFullTextOnHover) {
    ui::AppState state;
    state.live.error = "Permission denied: capturing needs access to /dev/bpf* (macOS) or CAP_NET_RAW (Linux) "
                       "(Attempt to open /dev/bpf0 failed - root privileges may be required)";
    state.loadMessage = "Warning: " + std::string(200, 'x');
    ImVec2 errorHover;
    for (const float width: {1280.0f, 640.0f}) {
        if (width == 640.0f) {
            state.currentFile = "/capture.pcap";
            for (int i = 0; i < 80; ++i) state.displayName += "ölçüm";
            state.displayName += ".pcap";
            state.filter.active = true;
            state.filter.appliedText = "tcp && " + std::string(100, 'x');
            state.live.error += "\nMore details: " + std::string(100, 'x');
        }
        ImGui::GetIO().DisplaySize = ImVec2(width, 720);
        frames(state);
        ImGuiWindow *status = windowNamed("##status");
        ASSERT_NE(status, nullptr);
        float textRight = 0.0f;
        float errorLeft = width;
        bool hasError = false;
        const ImU32 textColor = ImGui::GetColorU32(ImGuiCol_Text);
        const ImU32 errorColor = ImGui::ColorConvertFloat4ToU32(ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
        for (const ImDrawVert &v: status->DrawList->VtxBuffer) {
            if (v.col == textColor) textRight = std::max(textRight, v.pos.x);
            if (v.col == errorColor) {
                hasError = true;
                errorLeft = std::min(errorLeft, v.pos.x);
                EXPECT_LE(v.pos.x, width - ImGui::GetStyle().WindowPadding.x);
            }
        }
        ASSERT_TRUE(hasError);
        EXPECT_GE(errorLeft, width * 0.5f);
        EXPECT_LT(textRight, errorLeft);
        EXPECT_LE(status->ContentSize.x, width - 2 * ImGui::GetStyle().WindowPadding.x);
        errorHover = ImVec2((errorLeft + width - ImGui::GetStyle().WindowPadding.x) * 0.5f,
                            status->Pos.y + ImGui::GetStyle().WindowPadding.y + ImGui::GetFontSize() * 0.5f);
    }

    moveTo(state, errorHover);
    std::string log;
    frame(state, &log);
    std::istringstream errorLines(state.live.error);
    for (std::string line; std::getline(errorLines, line);) EXPECT_NE(log.find(line), std::string::npos) << log;
    EXPECT_NE(log.find(state.loadMessage), std::string::npos) << log;
}

TEST_F(UiInteract, StatusBarOfALiveSessionKeepsTheCaptureText) {
    ui::AppState state;
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    frames(state);
    const ui::StatusSegments seg = ui::statusSegments(state);
    EXPECT_EQ(seg.left, "Capturing on fake0 - 0 packets, 0 dropped");
    EXPECT_EQ(seg.displayed, "Displayed: 0 / 0");
}
