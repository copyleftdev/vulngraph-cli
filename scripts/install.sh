#!/bin/sh
# Install the vulngraph CLI to ~/.local/bin (or $VULNGRAPH_INSTALL_DIR).
#
# Overrides:
#   VULNGRAPH_VERSION       release tag (default: latest)
#   VULNGRAPH_INSTALL_DIR   install directory (default: $HOME/.local/bin)
#   VULNGRAPH_RELEASE_BASE  release asset base URL (for mirrors/testing)
set -eu

REPO="copyleftdev/vulngraph-cli"
INSTALL_DIR="${VULNGRAPH_INSTALL_DIR:-$HOME/.local/bin}"

os="$(uname -s)"
arch="$(uname -m)"
case "$os-$arch" in
  Linux-x86_64)   target="x86_64-unknown-linux-musl" ;;
  Darwin-arm64)   target="aarch64-apple-darwin" ;;
  *)
    echo "unsupported platform: $os-$arch" >&2
    echo "prebuilt binaries: Linux x86_64, macOS arm64. Try: cargo install --git https://github.com/$REPO" >&2
    exit 1
    ;;
esac

version="${VULNGRAPH_VERSION:-latest}"
if [ -n "${VULNGRAPH_RELEASE_BASE:-}" ]; then
  base="$VULNGRAPH_RELEASE_BASE"
elif [ "$version" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$version"
fi

# The archive is named vulngraph-<tag>-<target>.tar.gz; when installing
# "latest" we cannot know the tag, so resolve it from the redirect.
if [ "$version" = latest ] && [ -z "${VULNGRAPH_RELEASE_BASE:-}" ]; then
  version="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')"
  base="https://github.com/$REPO/releases/download/$version"
fi

archive="vulngraph-$version-$target.tar.gz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$2" "$1"
  else
    wget -qO "$2" "$1"
  fi
}

echo "Downloading $archive ..."
fetch "$base/$archive" "$tmp/$archive"
fetch "$base/$archive.sha256" "$tmp/$archive.sha256"

echo "Verifying checksum ..."
( cd "$tmp" && (sha256sum -c "$archive.sha256" >/dev/null 2>&1 \
  || shasum -a 256 -c "$archive.sha256" >/dev/null 2>&1) ) \
  || { echo "checksum verification failed" >&2; exit 1; }

tar -xzf "$tmp/$archive" -C "$tmp"
mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/vulngraph-$version-$target/vulngraph" "$INSTALL_DIR/vulngraph"

echo "Installed vulngraph to $INSTALL_DIR/vulngraph"
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "Add $INSTALL_DIR to your PATH to use it." ;;
esac
echo "Next: vulngraph update"
