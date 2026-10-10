#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo="$(pwd)"

bin="${SCAN_BIN:-$(go env GOPATH)/bin}"
rules="${SEMGREP_RULES:-$HOME/tools/semgrep-rules}"
opengrep="${OPENGREP:-}"
if [ -z "$opengrep" ]; then
  for candidate in "$(command -v opengrep 2>/dev/null)" "$HOME/tools/opengrep/opengrep_windows_x86.exe" "$HOME/tools/opengrep/opengrep" "$HOME/.opengrep/cli/latest/opengrep"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ]; then
      opengrep="$candidate"
      break
    fi
  done
fi
export OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="${OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY:-$HOME/tools/osv-db}"
failed=()

step() {
  local name="$1"
  shift
  echo "== $name"
  if ! "$@"; then
    failed+=("$name")
  fi
}

gosec_reviewed=G104,G115,G103,G401,G405,G501,G502,G505,G301,G302,G304,G204
gosec_cli=$gosec_reviewed,G404,G702,G703,G704,G122

gosec_server() {
  "$bin/gosec" -fmt text -color=false -exclude="$gosec_reviewed" -exclude-dir=cmd ./... 2>/dev/null
}

gosec_cli() {
  "$bin/gosec" -fmt text -color=false -exclude="$gosec_cli" ./cmd/... 2>/dev/null
}

opengrep_reviewed=(
  go.lang.security.audit.use-of-unsafe-block
  go.lang.correctness.permissions.incorrect-default-permission
  go.lang.security.audit.xss.no-direct-write-to-responsewriter
  go.lang.security.audit.dangerous-exec-command
  go.lang.security.audit.dangerous-syscall-exec
  go.lang.security.audit.crypto.use-of-md5
  go.lang.security.audit.crypto.use-of-sha1
  go.lang.security.audit.crypto.use-of-DES
  go.lang.correctness.exported_loop_pointer
  go.lang.best-practice.hidden-goroutine
)

target() {
  if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

opengrep_code() {
  local skip=()
  for r in "${opengrep_reviewed[@]}"; do
    skip+=(--exclude-rule "$r")
  done
  (cd "$rules" && "$opengrep" scan --disable-version-check --quiet --error \
    --config go --config bash --config dockerfile "${skip[@]}" \
    --exclude testdata --exclude '*_test.go' --exclude web "$(target "$repo")")
}

opengrep_dashboard() {
  (cd "$rules" && "$opengrep" scan --disable-version-check --quiet --error \
    --config javascript --config html --exclude i18n --exclude '*.min.js' "$(target "$repo/web")")
}

step govulncheck "$bin/govulncheck" -test ./...
step osv-scanner "$bin/osv-scanner" scan source --offline --download-offline-databases -r .
step "gitleaks history" "$bin/gitleaks" git . --redact --no-banner
step "gitleaks staged" "$bin/gitleaks" git . --staged --redact --no-banner
step "gitleaks unstaged" "$bin/gitleaks" git . --pre-commit --redact --no-banner
step "gosec server" gosec_server
step "gosec cli" gosec_cli
step staticcheck "$bin/staticcheck" -checks inherit,-ST1005 ./...
step "go vet" go vet ./...
if [ -n "$opengrep" ] && [ -d "$rules" ]; then
  step "opengrep code" opengrep_code
  step "opengrep dashboard" opengrep_dashboard
else
  echo "== opengrep: not found (set OPENGREP and SEMGREP_RULES)" >&2
  failed+=("opengrep")
fi

if ((${#failed[@]})); then
  echo "failed: ${failed[*]}" >&2
  exit 1
fi
echo "all checks passed"
