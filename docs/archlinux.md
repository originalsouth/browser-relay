# Arch Linux / AUR

`packaging/aur/browser-relay-git` is an AUR-ready recipe for the current `main`
branch. It is **not published to AUR yet**. There are no release tags, so this is
a VCS package: its version combines Cargo's version, the Git commit count and a
short commit ID. It provides and conflicts with `browser-relay`.

## Build and install

On Arch, install `base-devel` and `git`, then review the recipe and build as your
normal user:

```sh
git clone https://github.com/originalsouth/browser-relay.git
cd browser-relay/packaging/aur/browser-relay-git
makepkg -si
```

`makepkg` resolves the declared dependencies and runs the tests. Cargo dependencies
are fetched using the lockfile during preparation; building and testing use
`--frozen`. Every package build forces release **fat LTO and one codegen unit**.
Arch's C/C++ LTO is disabled for compatibility with ring; Rust LTO stays enabled.
The recipe currently declares x86_64, the architecture covered by CI.

The package installs `/usr/bin/browser-relay`, the application-menu entry, the
SVG icon and MIT license. Pacman's standard desktop/icon hooks handle cache
refreshes. It does not run the per-user installer, change browser defaults, grant
ping capabilities, or download reputation/GeoIP datasets. Install `wl-clipboard`
for Wayland copying, or `xclip`/`xsel` for X11. Zenity is an optional fallback.

Select Browser Relay in your desktop's default-app settings, or run:

```sh
xdg-settings set default-web-browser browser-relay.desktop
xdg-mime default browser-relay.desktop x-scheme-handler/http x-scheme-handler/https
```

If you used `./install.sh` previously, run that installation's `uninstall.sh` before
switching: its `~/.local/bin` binary and per-user desktop entry can shadow the
system package. Remove the Arch package with `sudo pacman -Rns browser-relay-git`;
choose another default browser first. User data is kept.

## Automation

The [Arch Linux workflow](https://github.com/originalsouth/browser-relay/actions/workflows/archlinux.yml)
runs on pushes, pull requests and manual dispatches in an Arch `base-devel`
container. It verifies `.SRCINFO`, builds and tests as an unprivileged user, runs
namcap, installs the result in the disposable container and smoke-tests it.

CI redirects only the recipe's upstream Git URL to a local mirror of the exact
workflow commit. A PR therefore tests its own code, even though the AUR recipe
tracks `main`. It retains a binary package, an AUR source bundle with regenerated
metadata, the source commit ID and diagnostics. Artifacts expire after 14 days;
logs expire after seven. Packages are unsigned test builds.

AUR users rebuild with `makepkg` or their helper's development-package update mode
to pick up new commits. VCS recipes do not need a metadata-only AUR push for every
upstream commit. When dependencies or packaging change, regenerate metadata:

```sh
./packaging/aur/update-srcinfo.sh
```

If the desktop entry changes, refresh its checksum with `updpkgsums` (from
`pacman-contrib`) in the recipe directory before regenerating metadata.

To run the same package build locally against a **committed** checkout:

```sh
./packaging/aur/ci-build.sh "$PWD" /tmp/browser-relay-arch
```

## First AUR submission

The separate AUR repository needs these three files at its root: `PKGBUILD`,
`.SRCINFO`, and `browser-relay.desktop`. Register an AUR account/SSH key, confirm
the package name is available, then review and push those files to the AUR
repository's `master` branch. The generated `browser-relay-git-aur.tar.gz` contains
the same submission files. Never upload the built binary or Cargo sources to AUR.

## Enable automatic AUR publishing

The Arch workflow has an optional `publish` job after the package build, tests,
namcap and installation smoke test succeed. It accepts pushes and manual runs on
`main` in `originalsouth/browser-relay`; pull requests cannot publish. It checks
that the tested commit is still current before preparing and pushing an update.
No AUR credentials are passed to the build job.

One-time GitHub setup:

1. Add a dedicated, unattended SSH public key to your AUR account. That account
   must own or co-maintain `browser-relay-git`, or be able to create it if available.
2. Create a GitHub Actions **environment named `aur`**, restricted to the `main`
   deployment branch. You can add required reviewers if you want manual approval
   before each publication.
3. Add these **environment secrets**:
   - `AUR_SSH_PRIVATE_KEY`: the matching private key (without a passphrase).
   - `AUR_KNOWN_HOSTS`: a verified OpenSSH known-hosts entry for `aur.archlinux.org`,
     copied from a trusted SSH configuration after checking the server fingerprint
     against Arch's published host keys. The workflow never blindly accepts a
     scanned host key.
4. Add **environment variables** `AUR_GIT_NAME` and `AUR_GIT_EMAIL` for the AUR
   commit author. These AUR commits use that identity; they do not use your local
   GPG signing key.
5. Set the **repository Actions variable** `AUR_PUBLISH_ENABLED` to `true`.
6. Run **Actions → Arch Linux → Run workflow** on `main` for the first publication.
   Subsequent successful builds of `main` sync packaging changes automatically.

The publisher reads the three checked-in recipe files from the tested commit,
not a downloaded PR artifact. It does not execute the AUR checkout's PKGBUILD.
It commits only changes to managed files, preserves unrelated maintainer files,
skips VCS version-only changes, and pushes to `master` without force. Concurrent
AUR edits cause a rejected push; rerun the workflow after reviewing them. An empty
AUR repository is supported for the first submission.

Publication jobs are serialized. Credentials are scoped to the publishing step,
stored in temporary files with private permissions, and removed afterwards.
Unset `AUR_PUBLISH_ENABLED` or set it to `false` to disable publication while
retaining package builds. This automation has local regression coverage; a live
AUR push still requires your account setup and credentials.

See the [AUR submission guidelines](https://wiki.archlinux.org/title/AUR_submission_guidelines)
and [GitHub environment setup](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).
