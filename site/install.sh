#!/bin/sh
# vio installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/ThembinkosiThemba/vio/main/site/install.sh | sh
#
# Environment overrides:
#   VIO_VERSION      release tag to install (default: latest), e.g. v0.1.0
#   VIO_INSTALL_DIR  where to put the binary (default: /usr/local/bin if writable, else ~/.local/bin)
#   VIO_DOWNLOAD_URL base URL for release assets (mirrors, testing)
#
# The whole script is wrapped in main() so a partially downloaded script never runs.

set -eu

REPO="ThembinkosiThemba/vio"

say()  { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
err()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
has()  { command -v "$1" >/dev/null 2>&1; }

download() { # url dest
  if has curl; then
    curl -fsSL --proto '=https,file' --tlsv1.2 -o "$2" "$1"
  elif has wget; then
    wget -q -O "$2" "$1"
  else
    err "need curl or wget"
  fi
}

sha256() {
  if has sha256sum; then sha256sum "$1" | cut -d' ' -f1
  elif has shasum; then shasum -a 256 "$1" | cut -d' ' -f1
  else err "need sha256sum or shasum to verify the download"
  fi
}

main() {
  has tar || err "need tar"
  has uname || err "need uname"

  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$os" in
    linux|darwin) ;;
    *) err "unsupported OS '$os'. On Windows run: irm https://raw.githubusercontent.com/$REPO/main/site/install.ps1 | iex" ;;
  esac

  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) err "unsupported architecture '$arch'" ;;
  esac

  version="${VIO_VERSION:-latest}"
  if [ -n "${VIO_DOWNLOAD_URL:-}" ]; then
    base="$VIO_DOWNLOAD_URL"
  elif [ "$version" = latest ]; then
    base="https://github.com/$REPO/releases/latest/download"
  else
    base="https://github.com/$REPO/releases/download/$version"
  fi

  archive="vio_${os}_${arch}.tar.gz"
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT INT TERM

  say "Installing vio ($version, $os/$arch)"
  info "downloading $archive"
  download "$base/$archive" "$tmp/$archive" || err "download failed: $base/$archive"
  download "$base/checksums.txt" "$tmp/checksums.txt" || err "download failed: $base/checksums.txt"

  # Accept both "hash  file" and binary-mode "hash *file" lines.
  expected=$(awk -v f="$archive" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/checksums.txt")
  [ -n "$expected" ] || err "no checksum for $archive in checksums.txt"
  actual=$(sha256 "$tmp/$archive")
  [ "$expected" = "$actual" ] || err "checksum mismatch for $archive (expected $expected, got $actual)"
  info "checksum verified"

  tar -xzf "$tmp/$archive" -C "$tmp" vio || err "could not extract vio from $archive"

  dir="${VIO_INSTALL_DIR:-}"
  if [ -z "$dir" ]; then
    if [ -w /usr/local/bin ]; then dir=/usr/local/bin; else dir="$HOME/.local/bin"; fi
  fi
  mkdir -p "$dir"
  cp "$tmp/vio" "$dir/vio.tmp"
  chmod 0755 "$dir/vio.tmp"
  mv -f "$dir/vio.tmp" "$dir/vio"
  info "installed $dir/vio"

  case ":$PATH:" in
    *":$dir:"*) ;;
    *)
      printf '\n'
      info "$dir is not on your PATH. Add it with:"
      info "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile && . ~/.profile"
      ;;
  esac

  printf '\n'
  say "Done. Start chatting with your servers:"
  info "vio"
}

main "$@"
