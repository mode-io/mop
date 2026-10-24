# Install MOP

MOP and its packages are publicly available. No GitHub account is required.
MOP runs on Linux with Python 3.10 or newer. Packages install `mop`, `hmop`, and `bmop`; models and privileged collectors are configured separately.

## Homebrew on Linux

```bash
brew install mode-io/tap/mop
```

Update with `brew update && brew upgrade mode-io/tap/mop`.
This is the modeio tap. macOS and Windows monitoring are not supported.

## Debian / Ubuntu

Add the signed APT repository and install MOP in one command:

```bash
curl -fsSL https://github.com/mode-io/mop/releases/download/apt/setup-apt.sh | sudo bash
```

After the initial setup:

```bash
sudo apt install mop
sudo apt upgrade
```

The setup script installs `/usr/share/keyrings/modeio-mop.gpg` and `/etc/apt/sources.list.d/modeio-mop.sources`. APT verifies the repository signature and package hashes. The signing key is scoped to this source with `Signed-By`.

Public key fingerprint: `C94233E80CC367A5C21CDC23737CB9C3307434B1`.

This is modeio's package source, not the distribution's default repository.

## Fedora / RHEL, Arch, and other Linux systems

```bash
curl -fsSL https://github.com/mode-io/mop/releases/download/v0.9.4/install.sh | bash
```

The installer checks the download and selects DNF, YUM, Pacman, or a user-prefix installation. It also supports local DEB installation; Debian/Ubuntu users should prefer the APT source above for ongoing updates.

To choose a method:

```bash
curl -fsSL https://github.com/mode-io/mop/releases/download/v0.9.4/install.sh | bash -s -- --method user
```

Choose `apt`, `dnf`, `yum`, `pacman`, or `user`. Use `--dry-run` to see the selection without installing. User installation needs Python 3.10+ with curses, uses `~/.local`, and does not need sudo.

## uv / pipx

```bash
uv tool install 'git+https://github.com/mode-io/mop.git@v0.9.4'
```

Or:

```bash
pipx install https://github.com/mode-io/mop/releases/download/v0.9.4/modeio_mop-0.9.4-py3-none-any.whl
```

Python-tool installs include the declared tracing/tokenizer dependencies. Native core packages use the standard library and a conservative byte-budget fallback. The wheel is distributed on GitHub Releases; the short package name is not published to PyPI yet.

## Download packages directly

| System | Asset | Install after downloading |
| --- | --- | --- |
| Debian / Ubuntu | `mop_0.9.4_all.deb` | `sudo apt install ./mop_0.9.4_all.deb` |
| Fedora / RHEL | `mop-0.9.4-1.noarch.rpm` | `sudo dnf install ./mop-0.9.4-1.noarch.rpm` |
| Arch | `mop-0.9.4-1-any.pkg.tar.zst` | `sudo pacman -U ./mop-0.9.4-1-any.pkg.tar.zst` |
| Other Linux | `mop-0.9.4-linux-any.tar.gz` | Use `install.sh --method user` |

[Download release assets](https://github.com/mode-io/mop/releases/tag/v0.9.4). The release includes `SHA256SUMS` and `manifest.json`.

## Start and remove

```bash
mop
hmop
bmop
mop doctor
```

[Connect OpenJev](jev-2b-batching.md) · [Enable deep capture](system-install.md#full-capture)

Python function capture needs VizTracer 1.1.1 in the interpreter running your task. Native packages do not modify that interpreter. Runtime files use the XDG state directory; `MOP_RUNTIME_DIR` can override the runtime path.

Remove with `sudo apt remove mop`, `sudo dnf remove mop`, `sudo pacman -R mop`, or `brew uninstall mode-io/tap/mop`. User-prefix installations live in `~/.local/lib/modeio-mop` with three links under `~/.local/bin`. User state is retained.

## Release maintenance

Build packages with Python and nFPM 2.48.0:

```bash
python3 -m pip wheel --no-deps --wheel-dir dist/packages .
python3 scripts/build-packages.py --nfpm /path/to/nfpm
```

Build and verify APT metadata on Linux with GnuPG and apt-utils:

```bash
python3 scripts/build-apt-repository.py
python3 scripts/check-apt-repository.py
```

The dedicated private signing key lives under `.runtime/release-signing/gnupg` on the release host. Keep a private backup; never commit or upload that directory. Use `--initialize-key` only for the first setup, not for routine releases. Metadata expires after 180 days; refresh and publish it before expiry.

Keep versioned DEB assets immutable and available. Upload new DEBs and indexes to the `apt` release, then publish `InRelease` last. Do not upload private key files. Application releases remain separate from the repository-metadata release.

Keep the version synchronized in `pyproject.toml`, `mop/__init__.py`, and `packaging/install.sh`. Render `packaging/mop.rb.in` with the version and final Git commit for the Homebrew tap. GitHub Actions remains disabled; publication is manual.

Validation for 0.9.4: public release downloads and repository signatures were verified. APT installation/removal passed against a local copy of the published repository, including all three entry points. The release host's online APT transaction could not be completed because its connection to GitHub timed out. The Python regression suite passed 331 tests with 10 skips. Earlier 0.9.3 validation covered user-prefix installation, repeat installation, checksum rejection, and existing-command protection. RPM/Arch metadata and payloads were inspected; complete DNF, Pacman, and Linuxbrew transactions have not been exercised.
