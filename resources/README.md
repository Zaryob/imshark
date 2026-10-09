# ImShark branding

`logo.png` is the supplied original artwork. `welcome-logo.png` (dark lettering, for light mode) and `welcome-logo-light.png` (light lettering, for dark mode) are 1024 × 512 copies embedded in the executable, so they do not depend on the launch directory. The welcome screen renders them transparently matching the active theme.

The platform icons use the same artwork on a light rounded square:

- `imshark.icns`: macOS Finder and Dock, copied into the `.app` bundle.
- `imshark.ico` and `imshark.rc`: Windows executable icon.
- `imshark.png`: Linux desktop/AppImage icon and GLFW window icon on Windows/Linux.
- `imshark-1024.png`: full-resolution icon preview.

The generated assets are checked in; building requires no image conversion tools. To regenerate them after replacing `logo.png`, run `node tools/make_brand_assets.cjs` with the `sharp` package installed. Generate the `.icns` on macOS, where the script uses the system `iconutil` tool.
