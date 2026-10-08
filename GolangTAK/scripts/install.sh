#!/bin/sh
set -eu

REPO="grangedevgroup-code/TAK-Backend"
TAG_PREFIX="golangtak-v"
MODULE="github.com/grangedevgroup-code/TAK-Backend/GolangTAK/cmd/golangtak"

say() { printf '%s\n' "$*"; }
die() { printf 'golangtak installer: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

detect_os() {
	case "$(uname -s)" in
		Linux) echo linux ;;
		Darwin) echo darwin ;;
		FreeBSD) echo freebsd ;;
		OpenBSD) echo openbsd ;;
		NetBSD) echo netbsd ;;
		*) die "unsupported operating system: $(uname -s)" ;;
	esac
}

detect_arch() {
	m="$(uname -m)"
	case "$m" in
		x86_64 | amd64) echo amd64 ;;
		aarch64 | arm64 | armv8*) echo arm64 ;;
		armv7* | armhf) echo armv7 ;;
		armv6* | arm) echo armv6 ;;
		armv5*) echo armv5 ;;
		i386 | i486 | i586 | i686 | x86) echo 386 ;;
		riscv64) echo riscv64 ;;
		ppc64le) echo ppc64le ;;
		s390x) echo s390x ;;
		loongarch64) echo loong64 ;;
		mips64)
			if [ "$(endian)" = little ]; then echo mips64le; else echo mips64; fi ;;
		mips)
			if [ "$(endian)" = little ]; then echo mipsle; else echo mips; fi ;;
		mipsel | mipsle) echo mipsle ;;
		*) die "unsupported processor: $m" ;;
	esac
}

endian() {
	if [ -r /sys/kernel/cpu_byteorder ]; then
		cat /sys/kernel/cpu_byteorder
		return
	fi
	v="$(printf 'I' | od -An -tx2 2>/dev/null | tr -d ' \n')"
	if [ "$v" = "0049" ] || [ "$v" = "49" ]; then echo little; else echo big; fi
}

download() {
	url="$1"
	out="$2"
	if have curl; then
		curl -fsSL --retry 3 --connect-timeout 20 -o "$out" "$url"
	elif have wget; then
		wget -q -T 30 -t 3 -O "$out" "$url"
	elif have fetch; then
		command fetch -q -o "$out" "$url"
	elif [ "$(uname -s)" = OpenBSD ] || [ "$(uname -s)" = NetBSD ]; then
		ftp -V -o "$out" "$url" >/dev/null
	else
		die "curl or wget is required"
	fi
}

sha256() {
	if have sha256sum; then
		sha256sum "$1" | awk '{print $1}'
	elif have shasum; then
		shasum -a 256 "$1" | awk '{print $1}'
	elif have sha256; then
		sha256 -q "$1"
	elif have openssl; then
		openssl dgst -sha256 "$1" | awk '{print $NF}'
	else
		echo ""
	fi
}

latest_tag() {
	api="https://api.github.com/repos/$REPO/releases?per_page=50"
	tmpjson="$WORK/releases.json"
	if download "$api" "$tmpjson" 2>/dev/null; then
		grep -o "\"tag_name\": *\"${TAG_PREFIX}[^\"]*\"" "$tmpjson" | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/'
	fi
}

make_workdir() {
	for base in "${TMPDIR:-/tmp}" /var/tmp "$HOME"; do
		if [ ! -d "$base" ] || [ ! -w "$base" ]; then
			continue
		fi
		d="$base/golangtak-install.$$"
		mkdir -p "$d" 2>/dev/null || continue
		printf '#!/bin/sh\nexit 0\n' > "$d/probe"
		chmod +x "$d/probe"
		if "$d/probe" 2>/dev/null; then
			rm -f "$d/probe"
			echo "$d"
			return
		fi
		rm -rf "$d"
	done
	die "no writable directory that allows running programs was found"
}

build_from_source() {
	have go || return 1
	say "Building GolangTAK from source with $(go version)"
	ref="${GOLANGTAK_VERSION:-latest}"
	case "$ref" in
		latest | v*) ;;
		*) ref="v$ref" ;;
	esac
	GOBIN="$WORK" CGO_ENABLED=0 go install -trimpath -ldflags "-s -w" "$MODULE@$ref" || return 1
	[ -x "$WORK/golangtak" ] || return 1
	BIN="$WORK/golangtak"
}

main() {
	OS="$(detect_os)"
	ARCH="$(detect_arch)"
	WORK="$(make_workdir)"
	trap 'rm -rf "$WORK"' EXIT INT TERM
	BIN=""

	if [ -n "${GOLANGTAK_BINARY:-}" ]; then
		[ -f "$GOLANGTAK_BINARY" ] || die "GOLANGTAK_BINARY does not exist: $GOLANGTAK_BINARY"
		cp "$GOLANGTAK_BINARY" "$WORK/golangtak"
		chmod +x "$WORK/golangtak"
		BIN="$WORK/golangtak"
	elif [ "${GOLANGTAK_SOURCE:-0}" != "1" ]; then
		if [ -n "${GOLANGTAK_VERSION:-}" ] && [ "$GOLANGTAK_VERSION" != latest ]; then
			TAG="$TAG_PREFIX${GOLANGTAK_VERSION#v}"
		else
			TAG="$(latest_tag || true)"
		fi
		if [ -n "$TAG" ]; then
			asset="golangtak-$OS-$ARCH"
			base="https://github.com/$REPO/releases/download/$TAG"
			say "Downloading GolangTAK ${TAG#"$TAG_PREFIX"} for $OS/$ARCH"
			if download "$base/$asset" "$WORK/golangtak" && download "$base/SHA256SUMS" "$WORK/SHA256SUMS"; then
				want="$(awk -v a="$asset" '{n = $2; sub(/^\*/, "", n); if (n == a) { print $1; exit } }' "$WORK/SHA256SUMS")"
				got="$(sha256 "$WORK/golangtak")"
				if [ -z "$want" ]; then
					die "no checksum published for $asset"
				fi
				if [ -n "$got" ] && [ "$got" != "$want" ]; then
					die "checksum mismatch for $asset (expected $want, got $got)"
				fi
				[ -n "$got" ] || say "No SHA-256 tool found; skipping checksum verification"
				chmod +x "$WORK/golangtak"
				BIN="$WORK/golangtak"
			else
				say "Download failed."
				rm -f "$WORK/golangtak"
			fi
		else
			say "Could not find a GolangTAK release."
		fi
	fi

	if [ -z "$BIN" ]; then
		build_from_source || die "could not download or build GolangTAK. Install Go (https://go.dev/dl/) and run this again, or download a release from https://github.com/$REPO/releases"
	fi

	"$BIN" version || die "the downloaded program does not run on this system ($OS/$ARCH)"

	status=0
	if [ "$(id -u)" -ne 0 ]; then
		if have sudo; then
			sudo "$BIN" install "$@" || status=$?
		elif have doas; then
			doas "$BIN" install "$@" || status=$?
		else
			die "run this installer as root"
		fi
	else
		"$BIN" install "$@" || status=$?
	fi
	exit "$status"
}

main "$@"
