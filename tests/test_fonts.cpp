#include <gtest/gtest.h>

#include <imgui.h>

#include <ui/theme.h>

namespace {
    // A context of its own: the fonts are loaded once per ImGui context.
    struct FontContext {
        ImGuiContext *context = ImGui::CreateContext();
        ~FontContext() { ImGui::DestroyContext(context); }
    };

    bool hasGlyph(ImWchar c) { return ImGui::GetIO().Fonts->Fonts[0]->IsGlyphInFont(c); }
} // namespace

TEST(Fonts, TheEmbeddedFontAloneLacksTurkishLetters) {
    // Why the system font is merged in: without it ğ and ı in file names were drawn as '?'.
    FontContext ctx;
    ImFontConfig config;
    config.SizePixels = 14.0f;
    ImGui::GetIO().Fonts->AddFontDefaultVector(&config);
    EXPECT_TRUE(hasGlyph('A'));
    EXPECT_TRUE(hasGlyph(0x00FC)) << "u with diaeresis is in Latin-1";
    EXPECT_FALSE(hasGlyph(0x011F)) << "g with breve";
    EXPECT_FALSE(hasGlyph(0x0131)) << "dotless i";
}

TEST(Fonts, TurkishLettersComeFromTheSystemFont) {
    if (ui::fallbackFontPath().empty()) GTEST_SKIP() << "none of the known system fonts is installed";
    FontContext ctx;
    ui::loadFonts(14.0f);
    ASSERT_EQ(ImGui::GetIO().Fonts->Fonts.Size, 1) << "the system font is merged into the embedded one";
    EXPECT_TRUE(hasGlyph('A'));
    for (const ImWchar c: {ImWchar(0x011E), ImWchar(0x011F), ImWchar(0x0130), ImWchar(0x0131), ImWchar(0x015E), ImWchar(0x015F)}) {
        EXPECT_TRUE(hasGlyph(c)) << "U+" << std::hex << c;
    }
}
