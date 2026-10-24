#!/usr/bin/env bash
set -euo pipefail
# The release is pinned so the script, package, and checksums remain consistent.
version=0.9.4
repository=mode-io/mop
method=auto
prefix="${HOME}/.local"
dry_run=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --method) method="${2:?Supply a method}"; shift 2 ;;
        --prefix) prefix="${2:?Supply an absolute prefix}"; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        -h|--help) echo 'Usage: bash install.sh [--method auto|apt|dnf|yum|pacman|user] [--prefix PATH] [--dry-run]'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done
[ "$(uname -s)" = Linux ] || { echo 'MOP requires Linux; macOS and Windows are not supported.' >&2; exit 1; }
case "$method" in auto|apt|dnf|yum|pacman|user) ;; *) echo 'Unsupported installation method.' >&2; exit 2;; esac
if [ "$method" = auto ]; then
    method=user
    for candidate in apt dnf yum pacman; do
        if command -v "$candidate" >/dev/null 2>&1; then method="$candidate"; break; fi
    done
fi
case "$method" in
    apt) asset="mop_${version}_all.deb" ;;
    dnf|yum) asset="mop-${version}-1.noarch.rpm" ;;
    pacman) asset="mop-${version}-1-any.pkg.tar.zst" ;;
    user) asset="mop-${version}-linux-any.tar.gz" ;;
esac
printf 'MOP %s: %s installation (%s)\n' "$version" "$method" "$asset"
if [ "$dry_run" = 1 ]; then exit 0; fi
command -v sha256sum >/dev/null || { echo 'Install coreutils (sha256sum) first.' >&2; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
fetch() {
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
        gh release download "v${version}" --repo "$repository" --pattern "$1" --dir "$work"
    else
        command -v curl >/dev/null || { echo 'Install curl or GitHub CLI first.' >&2; return 1; }
        curl --fail --location --silent --show-error --connect-timeout 10 --max-time 120 \
            "https://github.com/${repository}/releases/download/v${version}/$1" -o "$work/$1" || {
                echo 'This release may require GitHub access. Run gh auth login, then retry.' >&2; return 1;
            }
    fi
}
fetch SHA256SUMS
fetch "$asset"
awk -v file="$asset" '$2 == file {print}' "$work/SHA256SUMS" > "$work/selected.sha256"
[ "$(wc -l < "$work/selected.sha256")" -eq 1 ] || { echo 'Missing or ambiguous package checksum.' >&2; exit 1; }
(cd "$work" && sha256sum --check selected.sha256)
if [ "$method" = user ]; then
    command -v python3 >/dev/null || { echo 'Install Python 3.10+ first.' >&2; exit 1; }
    python3 -I -c 'import sys,curses; assert sys.version_info >= (3,10), "Python 3.10+ required"'
    case "$prefix" in /*) ;; *) echo 'Use an absolute --prefix.' >&2; exit 2;; esac
    destination="$prefix/lib/modeio-mop/$version"
    for name in mop hmop bmop; do
        target="$prefix/bin/$name"
        if [ -e "$target" ] || [ -L "$target" ]; then
            [ -L "$target" ] || { echo "Refusing to replace $target" >&2; exit 1; }
            case "$(readlink "$target")" in "$prefix/lib/modeio-mop/"*/bin/"$name") ;; *) echo "Refusing to replace $target" >&2; exit 1;; esac
        fi
    done
    mkdir -p "$prefix/lib/modeio-mop" "$prefix/bin"
    staged="$(mktemp -d "$prefix/lib/modeio-mop/.install-XXXXXX")"
    trap 'rm -rf -- "$work" "${staged:-}"' EXIT
    tar -xzf "$work/$asset" -C "$staged"
    # Use the interpreter actually checked above, rather than assuming /usr/bin/python3.
    python3 -I - "$staged" "$(command -v python3)" <<'PY'
from pathlib import Path
import sys
for p in (Path(sys.argv[1])/'bin').iterdir():
    lines=p.read_text().splitlines();lines[0]='#!'+sys.argv[2]+' -I';p.write_text('\n'.join(lines)+'\n')
PY
    "$staged/bin/mop" --version
    if [ -e "$destination" ]; then
        echo "Version $version already exists at $destination; keeping it."
        "$destination/bin/mop" --version
    else mv "$staged" "$destination"; staged=''; fi
    for name in mop hmop bmop; do ln -sfn "$destination/bin/$name" "$prefix/bin/$name"; done
    case ":$PATH:" in *":$prefix/bin:"*) ;; *) printf 'Add to your shell profile: export PATH="%s/bin:$PATH"\n' "$prefix";; esac
else
    command -v "$method" >/dev/null || { echo "Install $method first." >&2; exit 1; }
    elevate=()
    if [ "$(id -u)" -ne 0 ]; then elevate=(sudo); fi
    case "$method" in
        apt) "${elevate[@]}" apt-get install -y "$work/$asset" ;;
        dnf|yum) "${elevate[@]}" "$method" install -y "$work/$asset" ;;
        pacman) "${elevate[@]}" pacman -U --noconfirm "$work/$asset" ;;
    esac
fi
printf '\nInstalled. Run mop, hmop, or bmop.\n'
printf 'AI review: connect a running model. Setup: https://github.com/%s/blob/main/docs/system-install.md\n' "$repository"
