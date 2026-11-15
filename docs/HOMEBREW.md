# Homebrew

The macOS cask for ImShark is kept in the [Zaryob/tapir](https://github.com/Zaryob/tapir) tap, together with packages from
other Zaryob projects. It installs the published Apple Silicon DMG on macOS 15 or later, puts `imshark.app` into
Applications and links the `imshark` command. Nothing has to be compiled.

## Install, update, remove

```sh
brew tap zaryob/tapir https://github.com/Zaryob/tapir.git
brew install --cask zaryob/tapir/imshark
```

The app is signed ad hoc, without a Developer ID or notarization. If macOS blocks the first start, allow it under
System Settings > Privacy & Security > Open Anyway. The same approval is needed before `imshark --version` or
`imshark capture.pcap` work in the terminal. For live capture permissions see [Capture privileges](CAPTURE_PRIVILEGES.md).

```sh
brew update
brew upgrade --cask zaryob/tapir/imshark

brew uninstall --cask zaryob/tapir/imshark
brew untap zaryob/tapir   # only if no other package from the tap is used
```

## Updating the cask after a release

1. Download `imshark-<version>-macos-arm64.dmg` and `SHA256SUMS.txt` from the release and check the DMG with
   `shasum -a 256`.
2. In `Zaryob/tapir`, set `version` and `sha256` in `Casks/imshark.rb`. Only point it at assets that exist on the
   release. Check the deployment target of the app and its libraries before changing the macOS requirement.
3. Validate and submit the change as described in the [tap README](https://github.com/Zaryob/tapir#maintaining-packages).
   Users get it with `brew update` once it is on the tap's default branch.

A release does not update the cask by itself.
