# Releasing ImShark

This is the release procedure as `.github/workflows/release.yml` implements it. The workflow is the source of truth; if the two disagree, fix this document.

Only a pushed tag of the form `vMAJOR.MINOR.PATCH` starts a release. Branch pushes and pull requests run the regular CI (`ci.yml`) and never publish anything.

## 1. Pre-release checklist

- [ ] `master` is green: the latest CI run passed on Linux (debug with sanitizers, minimal), macOS (debug with sanitizers), Windows (default) and the Linux Docker job.
- [ ] All changes meant for the release are merged. Nothing else gets committed after the version bump.
- [ ] `CHANGELOG.md` has a section for the new version, and the `Unreleased` heading is renamed to it with the date (see [step 3](#3-update-the-changelog-and-write-the-release-notes)).
- [ ] `docs/releases/vX.Y.Z.md` exists and is not empty.
- [ ] `CMakeLists.txt` and `vcpkg.json` carry the new version (see [step 2](#2-bump-the-version)).
- [ ] `docs/KNOWN_ISSUES.md` and `docs/COMPATIBILITY.md` (if present) match what you are about to ship.
- [ ] Third-party notices are complete: the audit in [VALIDATION.md](VALIDATION.md#third-party-licence-notices-in-the-published-packages) still matches `vcpkg.json`. Re-check it after adding or removing a dependency.
- [ ] You have run the release build locally at least once: `cmake --preset default`, build, `ctest --preset default`.
- [ ] You have read the previous release's Actions run for warnings you want to avoid repeating.

## 2. Bump the version

The `validate` job requires the tag, the CMake project version and the vcpkg manifest version to be identical. Change both:

| File | What to change |
|---|---|
| `CMakeLists.txt` | `project(imshark VERSION X.Y.Z LANGUAGES CXX)` |
| `vcpkg.json` | `"version": "X.Y.Z"` |

The tag must be a stable SemVer tag: the validation regular expression rejects pre-release suffixes such as `-rc1`. `imshark --version` and the macOS bundle version are derived from `CMakeLists.txt`.

## 3. Update the changelog and write the release notes

1. In `CHANGELOG.md`, turn the `Unreleased` section into `X.Y.Z - YYYY-MM-DD` (or `[X.Y.Z]` with a link, like 0.9.2) and add a fresh empty `Unreleased` section above it when you start new work.
2. Create `docs/releases/vX.Y.Z.md`. Copy the previous file for the layout: a short description, the changes, and the Downloads table with the notes on checksums, live capture and the macOS signature. The `validate` job fails if the file is missing or empty, and the workflow publishes this file verbatim as the GitHub release body.
3. Commit the bump, changelog and notes together, for example `Bump version to X.Y.Z`.

## 4. Tag and push

Create an annotated tag on that commit and push the branch and that one tag atomically:

```sh
git tag -a vX.Y.Z -F docs/releases/vX.Y.Z.md
git push --atomic origin master refs/tags/vX.Y.Z
```

Do not use `git push --tags`: it would push every local tag, and any tag matching `v*` starts a release run.

### Never move or delete a published tag

Once a tag has been pushed and a workflow run has started, treat it as immutable, even when the run failed.

- Anyone may already have fetched the tag: forks, mirrors, package managers, users who cloned. A tag that later points to different source code breaks the rule that a version names exactly one source tree, and `git fetch` refuses to update a changed tag on their side, so they silently keep the old content.
- The release page, the checksums and the workflow run must correspond to a single commit. Moving the tag separates them.
- Fixes are cheap: the version number space is not scarce.

This is the history behind the rule. The `v0.9.0` tag produced no packages because the Windows test build failed. The `v0.9.1` run stopped when Docker Hub rate-limited the Linux GUI check and then timed out, before anything was built. Neither tag was moved or deleted. The fix for the Docker problem (pulling images through `mirror.gcr.io`) was committed and released as `v0.9.2`, which is why `v0.9.2` is the first published 0.9 release and the changelog marks 0.9.0 and 0.9.1 as not published.

If a tag was pushed by mistake (for example with a wrong version), do not delete it either: fix the cause and release the next patch version, and explain the gap in the changelog.

## 5. What the workflow does

`release.yml` runs these jobs in order:

| Job | What it checks or produces |
|---|---|
| `validate` | The tag matches `vMAJOR.MINOR.PATCH`; the CMake and vcpkg versions equal the tag; `docs/releases/<tag>.md` is not empty. An invalid tag stops here, before any compilation. |
| `checks` | Calls `ci.yml`: Linux debug build with sanitizers, Linux minimal build, macOS debug build with sanitizers, Windows default build, each with its tests; and the Linux Docker job (tests plus launching the GUI against Mesa software OpenGL without network access, then installing the DEB in a clean Ubuntu image and launching it). |
| `package` | One job per platform: Linux x86_64 on Ubuntu 24.04, macOS arm64, Windows x86_64. Each configures the `default` preset, builds, runs CTest, and runs `cpack`. Linux additionally runs `tools/linux_smoke.sh` and builds the AppImage with checksum-pinned linuxdeploy tools. Each job must find exactly one file per expected package pattern and uploads it as an artifact (kept 14 days). |
| `publish` | Needs `validate`, `checks` and every `package` job to succeed. It requires exactly the five expected packages, writes `SHA256SUMS.txt` and creates the GitHub release for the tag as the latest release, with `docs/releases/vX.Y.Z.md` as the body. |

The five assets, plus `SHA256SUMS.txt`:

- `imshark-X.Y.Z-linux-x86_64.tar.gz`, `.deb`, `.AppImage`
- `imshark-X.Y.Z-macos-arm64.dmg`
- `imshark-X.Y.Z-windows-x86_64.zip`

Nothing is published when any check or package job fails, so a failed run leaves no partial release. If an asset is missing or extra, `publish` fails with the difference.

## 6. When a job fails

First read the log and decide whether the failure is in the infrastructure or in the code.

- **Infrastructure or flaky failure** (registry rate limit, runner timeout, a download failing): open the run in the Actions tab and choose **Re-run failed jobs**. The rerun uses the same tag and commit, so nothing about the release changes. Rerunning is correct only when the code is certain to be fine. The `concurrency` group serialises runs of the same tag.
- **Code, test or packaging failure**: fix it on `master` with the normal pull request flow and release a new patch version (`X.Y.Z+1`) with a new tag, following steps 2 to 4. Describe the unpublished version in `CHANGELOG.md` as "not published" and say why, as for 0.9.0 and 0.9.1.
- **Failure of the `publish` job only**: use **Re-run failed jobs**; the package artifacts from the same run are reused if they are younger than 14 days. After that, release a new patch version.

Never fix a failed release by force-pushing the tag.

## 7. macOS signing

The macOS app is signed ad hoc (`codesign --force --deep --sign -`) as the last step of the install rule in `CMakeLists.txt`, after `fixup_bundle` has rewritten the library paths. The ad hoc signature is only there because Apple Silicon refuses to run unsigned code.

Developer ID signing and notarization are intentionally out of scope for 1.0. Consequences for users, which the release notes and the README state:

- Downloading the DMG with a browser marks the app as quarantined, and Gatekeeper refuses to open it on first launch with a message that it cannot verify the developer.
- To open it anyway: try to open ImShark once (it is blocked), then go to **System Settings > Privacy & Security**, scroll to the security section and choose **Open Anyway** next to the ImShark message, then confirm with your password. After that it opens normally.
- Users who prefer the terminal can remove the quarantine flag from the copied app: `xattr -dr com.apple.quarantine /Applications/imshark.app`. Only do this for a package whose checksum you verified.

When Developer ID signing is added later, it belongs in the install rule (replacing the ad hoc `codesign` call), plus a notarization and stapling step in the `package` job, and the notes about Gatekeeper should be removed from the README, `docs/BUILDING.md` and the release notes template.

## 8. Post-release checks

Do these from the published release page, not from your build directory.

1. The release is marked **Latest**, shows `docs/releases/vX.Y.Z.md` as its body, and lists the five packages and `SHA256SUMS.txt`.
2. Download the packages and compare their digests with `SHA256SUMS.txt`:
   ```sh
   shasum -a 256 imshark-X.Y.Z-macos-arm64.dmg      # macOS
   sha256sum --check --ignore-missing SHA256SUMS.txt # Linux
   ```
   ```powershell
   Get-FileHash imshark-X.Y.Z-windows-x86_64.zip -Algorithm SHA256   # Windows
   ```
3. macOS: open the DMG, copy `imshark.app` to Applications, open it with the Gatekeeper steps above, and check:
   ```sh
   /Applications/imshark.app/Contents/MacOS/imshark --version        # prints imshark X.Y.Z
   /usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' /Applications/imshark.app/Contents/Info.plist
   /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' /Applications/imshark.app/Contents/Info.plist
   codesign --verify --deep --strict /Applications/imshark.app
   ```
   The bundle identifier is `io.github.zaryob.imshark` and the version is X.Y.Z.
4. Linux: `./imshark-X.Y.Z-linux-x86_64.AppImage --version`, `sudo apt install ./imshark-X.Y.Z-linux-x86_64.deb` followed by `imshark --version`, and extract the tarball to check that `share/imshark/licenses` exists.
5. Windows: run the [clean machine checklist](#9-windows-clean-machine-checklist).
6. Open `tests/data/sample.pcap` (it is in the source tree) in at least one package and check that the packet list, detail tree and hex view fill.
7. The README download link points to `releases/latest`; confirm it resolves to the new release. If the README names the version anywhere, update it in a follow-up pull request.
8. Add a new `Unreleased` section to `CHANGELOG.md` if you did not do so in step 3.

## 9. Windows clean machine checklist

The automated checks run on a GitHub runner with the build tools installed. Before 1.0, and before any release that changes dependencies or packaging, test the ZIP on a Windows 10 or 11 x86_64 machine or virtual machine that has never had Visual Studio, vcpkg or ImShark installed. A fresh VM snapshot is ideal.

- [ ] Download `imshark-X.Y.Z-windows-x86_64.zip` and `SHA256SUMS.txt` with a browser; the digest from `Get-FileHash` matches.
- [ ] Extract the ZIP to a path that contains a space and a non-ASCII character, for example `C:\Users\Test User\İndirilenler\imshark`.
- [ ] `bin\imshark.exe --version` prints `imshark X.Y.Z` and does not report a missing DLL (a missing `VCRUNTIME140.dll` or `MSVCP140.dll` means the Visual C++ runtime was not bundled; this blocks the release).
- [ ] Double-click `bin\imshark.exe`: the window opens, shows the logo and welcome screen, and the window and taskbar carry the ImShark icon. Windows SmartScreen may warn about an unrecognised publisher because the binary is unsigned; record what it shows.
- [ ] Open `sample.pcap` through **File > Open** and by dragging it onto the window. The packet list, details and hex view fill.
- [ ] Apply a display filter such as `tcp`, clear it, and switch between dark and light themes.
- [ ] Close and reopen: the window size, position and recent files are remembered.
- [ ] Start live capture shows the expected guidance, because the Windows package has no live capture (live capture needs a separate Npcap-enabled build).
- [ ] The licence notices are present under `share\imshark\licenses`.
- [ ] Delete the extracted folder. Nothing is left behind except the settings file and temporary files in your profile.
- [ ] Record the Windows version, hardware or VM, who tested, the date and the package version, and add the result to [VALIDATION.md](VALIDATION.md).

Record failures as issues. A missing DLL, a crash on start or an unreadable file after a clean install blocks the release.
