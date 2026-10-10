# ImShark branding

`logo.png` is the supplied original artwork. `welcome-logo.png` (dark lettering, for light mode) and `welcome-logo-light.png` (light lettering, for dark mode) are 1024 × 512 copies embedded in the executable, so they do not depend on the launch directory. The welcome screen renders them transparently matching the active theme.

The platform icons use the same artwork on a light rounded square:

- `imshark.icns`: macOS Finder and Dock, copied into the `.app` bundle.
- `imshark.ico` and `imshark.rc`: Windows executable icon.
- `imshark.png`: Linux desktop/AppImage icon and GLFW window icon on Windows/Linux.
- `imshark-1024.png`: full-resolution icon preview.

The generated assets are checked in; building requires no image conversion tools. To regenerate them after replacing `logo.png`, run `node tools/make_brand_assets.cjs` with the `sharp` package installed. Generate the `.icns` on macOS, where the script uses the system `iconutil` tool.

## Source files that are not embedded

`logo.png` and `imshark-1024.png` are source and preview files. They are not embedded in the binary and are not installed into any package; they exist so that the derived assets can be regenerated. The executable embeds `welcome-logo.png`, `welcome-logo-light.png` and `imshark.png` (see `CMakeLists.txt`); `imshark.icns`, `imshark.ico` and `imshark.desktop` are used by the platform packaging.

## Licence

The ImShark logo and icon artwork in this directory (`logo.png` and every image derived from it: `welcome-logo*.png`, `imshark*.png`, `imshark.icns`, `imshark.ico`) was created by Süleyman Poyraz and is dedicated to the public domain under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/). You may copy, modify and use it for any purpose without asking permission or giving attribution.

This applies to the artwork only. ImShark's source code stays under GPL-3.0 (see `LICENSE`).
