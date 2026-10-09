#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
VERSION="${1:-${VERSION:-dev}}"
VERSION="${VERSION#golangtakserver-}"
VERSION="${VERSION#v}"
OUT="${OUT:-dist}"
TARGETS="${TARGETS:-linux/amd64 linux/arm64 linux/armv7 linux/armv6 linux/armv5 linux/386 linux/riscv64 linux/ppc64le linux/s390x linux/loong64 linux/mips linux/mipsle linux/mips64 linux/mips64le darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 windows/386 freebsd/amd64 freebsd/arm64 freebsd/386 freebsd/armv7 openbsd/amd64 openbsd/arm64 netbsd/amd64 netbsd/arm64 android/arm64}"

command -v go >/dev/null 2>&1 || { echo "Go is required: https://go.dev/dl/" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT"
for target in $TARGETS; do
	os="${target%/*}"
	arch="${target#*/}"
	goarch="$arch"
	goarm=""
	case "$arch" in
		armv7) goarch=arm goarm=7 ;;
		armv6) goarch=arm goarm=6 ;;
		armv5) goarch=arm goarm=5 ;;
	esac
	ext=""
	if [ "$os" = windows ]; then
		ext=".exe"
	fi
	name="golangtakserver-$os-$arch$ext"
	printf 'building %s\n' "$name"
	GOOS="$os" GOARCH="$goarch" GOARM="$goarm" GOMIPS=softfloat GOMIPS64=softfloat CGO_ENABLED=0 \
		go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/$name" ./cmd/golangtakserver
done

cd "$OUT"
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum golangtakserver-* | sed 's/ \*/  /' > SHA256SUMS
else
	shasum -a 256 golangtakserver-* > SHA256SUMS
fi
printf 'done: %s\n' "$(pwd)"
