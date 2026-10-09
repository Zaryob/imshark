#include <gtest/gtest.h>
#include <cstring>
#include <brand_assets.h>

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_NO_STDIO
#include <stb_image.h>

TEST(BrandAssets, EmbeddedLogoIsAValidPngWithExpectedDimensions) {
    ASSERT_GT(sizeof(brand::kLogoPng), 8u);
    const unsigned char pngMagic[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    EXPECT_EQ(std::memcmp(brand::kLogoPng, pngMagic, sizeof(pngMagic)), 0);

    int width = 0, height = 0, channels = 0;
    unsigned char *pixels = stbi_load_from_memory(brand::kLogoPng, static_cast<int>(sizeof(brand::kLogoPng)),
                                                  &width, &height, &channels, STBI_rgb_alpha);
    ASSERT_NE(pixels, nullptr) << (stbi_failure_reason() ? stbi_failure_reason() : "unknown failure");
    EXPECT_EQ(width, 1024);
    EXPECT_EQ(height, 512);
    EXPECT_EQ(channels, 4);
    stbi_image_free(pixels);
}

TEST(BrandAssets, EmbeddedIconIsAValidPngWithExpectedDimensions) {
    ASSERT_GT(sizeof(brand::kIconPng), 8u);
    const unsigned char pngMagic[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'};
    EXPECT_EQ(std::memcmp(brand::kIconPng, pngMagic, sizeof(pngMagic)), 0);

    int width = 0, height = 0, channels = 0;
    unsigned char *pixels = stbi_load_from_memory(brand::kIconPng, static_cast<int>(sizeof(brand::kIconPng)),
                                                  &width, &height, &channels, STBI_rgb_alpha);
    ASSERT_NE(pixels, nullptr) << (stbi_failure_reason() ? stbi_failure_reason() : "unknown failure");
    EXPECT_EQ(width, 256);
    EXPECT_EQ(height, 256);
    EXPECT_EQ(channels, 4);
    stbi_image_free(pixels);
}
