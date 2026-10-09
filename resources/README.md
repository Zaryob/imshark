# ImShark branding

`logo.png` is the supplied original artwork. `welcome-logo.png` is a 1024 × 512 copy embedded in the executable, so it does not depend on the launch directory. The welcome screen draws it on a light background for contrast in both themes.

The platform icons use the same artwork on a light rounded square:

- `imshark.icns`: macOS Finder and Dock, copied into the `.app` bundle.
- `imshark.ico` and `imshark.rc`: Windows executable icon.
- `imshark.png`: Linux desktop/AppImage icon and GLFW window icon on Windows/Linux.
- `imshark-1024.png`: full-resolution icon preview.

The generated assets are checked in; building requires no image conversion tools. To regenerate them after replacing `logo.png`, run `node tools/make_brand_assets.cjs` with the `sharp` package installed. Generate the `.icns` on macOS, where the script uses the system `iconutil` tool.
