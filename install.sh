#!/bin/sh
# bx installer — https://github.com/getkono/bx
#
#   curl -fsSL https://raw.githubusercontent.com/getkono/bx/master/install.sh | sh
#
# This is the only install channel. bx is what you run *before* you have a
# toolchain, so this script assumes nothing beyond a POSIX shell, curl or wget,
# and tar. The binary it fetches is statically linked against musl, so there is
# no glibc version floor and no shared library to find.
#
# Environment:
#   BX_VERSION      version to install, e.g. v1.2.3 (default: the latest release)
#   BX_INSTALL_DIR  where to put the binary (default: ~/.local/bin)

set -eu

REPO="getkono/bx"
INSTALL_DIR="${BX_INSTALL_DIR:-${HOME}/.local/bin}"

die() {
	printf '\033[31merror\033[0m: %s\n' "$1" >&2
	exit 1
}

info() {
	printf '\033[36m::\033[0m %s\n' "$1"
}

# --- preflight ----------------------------------------------------------------

[ "$(uname -s)" = "Linux" ] || die "bx is Linux-only; this is $(uname -s)."

case "$(uname -m)" in
x86_64 | amd64) ARCH="x86_64" ;;
aarch64 | arm64) ARCH="aarch64" ;;
*) die "unsupported architecture: $(uname -m). bx ships x86_64 and aarch64 binaries." ;;
esac
TARGET="${ARCH}-unknown-linux-musl"

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL "$1" -o "$2"; }
	fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -qO "$2" "$1"; }
	fetch_stdout() { wget -qO- "$1"; }
else
	die "neither curl nor wget is available."
fi

command -v tar >/dev/null 2>&1 || die "tar is required."

# Refuse to install without being able to verify what was downloaded. A tool
# that provisions credentials has no business running an unverified binary.
if command -v sha256sum >/dev/null 2>&1; then
	verify() { sha256sum -c "$1" >/dev/null 2>&1; }
elif command -v shasum >/dev/null 2>&1; then
	verify() { shasum -a 256 -c "$1" >/dev/null 2>&1; }
else
	die "neither sha256sum nor shasum is available; cannot verify the download."
fi

# --- resolve the version ------------------------------------------------------

VERSION="${BX_VERSION:-}"
if [ -z "$VERSION" ]; then
	info "Resolving the latest release..."
	VERSION=$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" |
		sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' |
		head -n 1)
	[ -n "$VERSION" ] || die "could not determine the latest release. Set BX_VERSION to install a specific one."
fi

ASSET="bx-${TARGET}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${VERSION}"

# --- download and verify ------------------------------------------------------

TMP=$(mktemp -d)
# shellcheck disable=SC2064 # TMP is expanded now, on purpose: it cannot change.
trap "rm -rf '$TMP'" EXIT INT TERM

info "Downloading bx ${VERSION} (${TARGET})..."
fetch "${BASE}/${ASSET}" "${TMP}/${ASSET}" || die "download failed: ${BASE}/${ASSET}"
fetch "${BASE}/${ASSET}.sha256" "${TMP}/${ASSET}.sha256" || die "checksum download failed: ${BASE}/${ASSET}.sha256"

info "Verifying checksum..."
(cd "$TMP" && verify "${ASSET}.sha256") || die "checksum mismatch — refusing to install."

tar -xzf "${TMP}/${ASSET}" -C "$TMP" || die "could not extract ${ASSET}."
[ -f "${TMP}/bx" ] || die "the archive did not contain an bx binary."

# --- install ------------------------------------------------------------------

mkdir -p "$INSTALL_DIR" || die "could not create ${INSTALL_DIR}."
chmod 755 "${TMP}/bx"
# Replace via rename so a running or concurrently-invoked bx is never a
# half-written file.
mv -f "${TMP}/bx" "${INSTALL_DIR}/bx" || die "could not install to ${INSTALL_DIR}."

# Two-letter names are a scarce namespace with no registry, so the long name is
# the one guaranteed to keep working: if `bx` ever collides on this machine, the
# user can delete it and lose nothing.
ln -sf bx "${INSTALL_DIR}/userbox" || die "could not link ${INSTALL_DIR}/userbox."

printf '\n\033[32m✓\033[0m Installed bx %s to %s\n' "$VERSION" "${INSTALL_DIR}/bx"
printf '  also available as %s\n\n' "${INSTALL_DIR}/userbox"

case ":${PATH}:" in
*":${INSTALL_DIR}:"*) ;;
*)
	printf '\033[33m!\033[0m %s is not on your PATH. Add it, then reopen your shell:\n' "$INSTALL_DIR"
	# shellcheck disable=SC2016 # $PATH is meant to reach the user literally.
	printf '    export PATH="%s:$PATH"\n\n' "$INSTALL_DIR"
	;;
esac

printf 'Next: \033[1mbx init\033[0m\n'
