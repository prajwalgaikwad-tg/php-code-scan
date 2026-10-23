#!/usr/bin/env bash
#
# php-security-scan — a universal, read-only security scanner for PHP apps.
#
# WHAT IT DOES
#   Runs on a server, auto-detects the application type (WordPress / Composer
#   framework / plain PHP), runs trusted free scanners, and produces one
#   plain-English HTML report plus a machine-readable JSON report. It never
#   modifies application code and never touches the database.
#
# TOOLS USED (all free, commercial-use safe)
#   - Semgrep CE          source-code vulnerability scan (fetched to bin/)
#   - composer audit      dependency CVE check (only if composer present)
#   - wp-cli              WordPress inventory (fetched to bin/, WP only)
#   - Wordfence feed      WordPress CVE matching (cached in cache/)
#   - built-in checks     config/file hardening + regex fallback
#
# USAGE
#   ./scan.sh [/path/to/application]              # scan a directory (default: CWD)
#   ./scan.sh --dangerous /path                   # report only Critical + High (dev-focused)
#   ./scan.sh --min-severity medium /path         # report Medium and above
#   ./scan.sh --s3 s3://bucket/prefix /path       # also upload the report to S3 (uses IAM role)
#   ./scan.sh --cleanup                           # remove fetched tools + cache, keep reports
#   ./scan.sh --no-fetch /path                    # never download; use only what is present
#   ./scan.sh --help
#
# Reports are written to reports/<hostname>_<timestamp>/ so multiple servers
# and multiple runs never overwrite each other.
#
# DESIGN
#   - Universal: no Docker, no root, no system package installs.
#   - Self-contained: everything lives in this folder (bin/, cache/, reports/).
#   - Portable: auto-detects OS + CPU arch (x86_64 / arm64) for binaries.
#   - Read-only on the target app; output only inside this folder.
#   - Works online (auto-fetch) or air-gapped (pre-bundled bin/ + cache/).
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$SCRIPT_DIR/bin"
CACHE_DIR="$SCRIPT_DIR/cache"
LIB_DIR="$SCRIPT_DIR/lib"

SEMGREP_BIN="$BIN_DIR/semgrep"          # may be a real binary or a wrapper
WP_CLI_PHAR="$BIN_DIR/wp-cli.phar"
WORDFENCE_FEED="$CACHE_DIR/wordfence-vulns.json"
WORDFENCE_URL="https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner"

# ---------------------------------------------------------------------------
# Colours / logging
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_BLU=$'\033[34m'; C_OFF=$'\033[0m'; C_BOLD=$'\033[1m'
else
  C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_OFF=""; C_BOLD=""
fi
log()  { printf '%s[scan]%s %s\n' "$C_BLU" "$C_OFF" "$*"; }
warn() { printf '%s[scan]%s %s\n' "$C_YEL" "$C_OFF" "$*"; }
ok()   { printf '%s[scan]%s %s\n' "$C_GRN" "$C_OFF" "$*"; }
err()  { printf '%s[scan]%s %s\n' "$C_RED" "$C_OFF" "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
DO_CLEANUP="no"
ALLOW_FETCH="yes"
MIN_SEVERITY="low"     # report findings at or above this level (default: all but info)
S3_DEST=""             # optional: s3://bucket[/prefix] to upload the report
TARGET=""

print_help() {
  sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --cleanup)   DO_CLEANUP="yes"; shift ;;
    --no-fetch)  ALLOW_FETCH="no"; shift ;;
    --min-severity) MIN_SEVERITY="${2:-low}"; shift 2 ;;
    --min-severity=*) MIN_SEVERITY="${1#*=}"; shift ;;
    --dangerous) MIN_SEVERITY="high"; shift ;;   # shorthand: critical + high only
    --s3)        S3_DEST="${2:-}"; shift 2 ;;    # upload report to s3://bucket[/prefix]
    --s3=*)      S3_DEST="${1#*=}"; shift ;;
    -h|--help)   print_help; exit 0 ;;
    --*)         err "Unknown option: $1"; exit 2 ;;
    *)           TARGET="$1"; shift ;;
  esac
done

# ---------------------------------------------------------------------------
# Cleanup mode: remove fetched tools + cache, keep reports
# ---------------------------------------------------------------------------
if [ "$DO_CLEANUP" = "yes" ]; then
  log "Cleanup: removing fetched tools and cached data (reports are kept)..."
  rm -rf "$BIN_DIR" "$CACHE_DIR"
  ok "Removed: bin/ and cache/"
  ok "Kept:    reports/"
  exit 0
fi

TARGET="${TARGET:-${TARGET_ENV:-$PWD}}"
TARGET="$(cd "$TARGET" 2>/dev/null && pwd || echo "$TARGET")"

# ---------------------------------------------------------------------------
# Host identity (for the report + unique report names)
# ---------------------------------------------------------------------------
HOSTNAME_FULL="$(hostname 2>/dev/null || echo unknown-host)"
# Primary non-loopback IPv4 (best-effort, works on Linux/macOS)
HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -z "$HOST_IP" ] && HOST_IP="$(ip -4 addr show scope global 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -1)"
[ -z "$HOST_IP" ] && HOST_IP="$(ipconfig getifaddr en0 2>/dev/null || true)"
[ -z "$HOST_IP" ] && HOST_IP="unknown"
# On EC2, grab instance metadata (IMDSv2) best-effort, non-fatal, short timeout.
EC2_INSTANCE_ID=""; EC2_REGION=""
if have curl; then
  _tok="$(curl -s --max-time 2 -X PUT "http://169.254.169.254/latest/api/token" \
          -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)"
  if [ -n "$_tok" ]; then
    EC2_INSTANCE_ID="$(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $_tok" \
      http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || true)"
    EC2_REGION="$(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $_tok" \
      http://169.254.169.254/latest/meta-data/placement/region 2>/dev/null || true)"
  fi
fi

# Sanitise hostname for use in a filename.
HOST_SLUG="$(printf '%s' "$HOSTNAME_FULL" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9._-' '-' | sed 's/-\{2,\}/-/g; s/^-//; s/-$//')"
[ -z "$HOST_SLUG" ] && HOST_SLUG="host"

STAMP="$(date +%Y%m%d-%H%M%S)"
# Report folder is prefixed with the host so multiple servers' reports never clash.
REPORT_NAME="${HOST_SLUG}_${STAMP}"
OUT_DIR="$SCRIPT_DIR/reports/$REPORT_NAME"
RAW_DIR="$OUT_DIR/raw"
JSON_FINDINGS="$OUT_DIR/findings.jsonl"   # one JSON object per line
mkdir -p "$RAW_DIR" "$BIN_DIR" "$CACHE_DIR"
: > "$JSON_FINDINGS"

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"; s="${s//$'\n'/\\n}"
  printf '%s' "$s"
}

# add_finding <severity> <category> <title> <description> <file> <line> <recommendation> <source>
add_finding() {
  printf '{"severity":"%s","category":"%s","title":"%s","description":"%s","file":"%s","line":"%s","recommendation":"%s","source":"%s"}\n' \
    "$(json_escape "$1")" "$(json_escape "$2")" "$(json_escape "$3")" "$(json_escape "$4")" \
    "$(json_escape "$5")" "$(json_escape "$6")" "$(json_escape "$7")" "$(json_escape "${8:-builtin}")" \
    >> "$JSON_FINDINGS"
}

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
echo
echo "${C_BOLD}PHP Security Scan${C_OFF}"
echo "  Target : $TARGET"
echo "  Output : $OUT_DIR"
echo

if [ ! -d "$TARGET" ]; then
  err "Target directory does not exist: $TARGET"
  exit 1
fi

# ---------------------------------------------------------------------------
# Platform detection (for portable binaries)
# ---------------------------------------------------------------------------
OS="$(uname -s)"      # Linux / Darwin
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64|amd64)   ARCH="x86_64" ;;
  aarch64|arm64)  ARCH="arm64"  ;;
  *)              ARCH="$ARCH_RAW" ;;
esac

# ---------------------------------------------------------------------------
# 1. Environment & app-type detection (read-only)
# ---------------------------------------------------------------------------
log "Detecting environment..."

IS_WORDPRESS="no"; IS_COMPOSER="no"; APP_TYPE="Plain PHP"
FRAMEWORK=""

if [ -f "$TARGET/wp-load.php" ] || [ -f "$TARGET/wp-config.php" ] || [ -d "$TARGET/wp-includes" ]; then
  IS_WORDPRESS="yes"; APP_TYPE="WordPress"
fi
if [ -f "$TARGET/composer.json" ]; then
  IS_COMPOSER="yes"
  [ "$APP_TYPE" = "Plain PHP" ] && APP_TYPE="PHP (Composer project)"
  # Light framework hinting (does not change behaviour, just labels the report)
  if [ -f "$TARGET/artisan" ]; then FRAMEWORK="Laravel"; APP_TYPE="Laravel"; fi
  if [ -f "$TARGET/bin/console" ] && grep -qi symfony "$TARGET/composer.json" 2>/dev/null; then
    FRAMEWORK="Symfony"; APP_TYPE="Symfony"
  fi
fi

PHP_VERSION="unknown"
have php && PHP_VERSION="$(php -r 'echo PHP_VERSION;' 2>/dev/null || echo unknown)"

# Internet check (quick, non-fatal)
INTERNET="no"
if have curl && curl -s --max-time 5 -o /dev/null -w '%{http_code}' https://semgrep.dev 2>/dev/null | grep -qE '^[23]'; then
  INTERNET="yes"
elif have wget && wget -q --timeout=5 --tries=1 -O /dev/null https://semgrep.dev 2>/dev/null; then
  INTERNET="yes"
fi

ok "Application type : $APP_TYPE"
ok "PHP version      : $PHP_VERSION"
ok "Platform         : $OS / $ARCH"
ok "Internet access  : $INTERNET"

PHP_FILE_COUNT="$(find "$TARGET" -type f -name '*.php' \
  -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null | wc -l | tr -d ' ')"
ok "PHP files        : $PHP_FILE_COUNT (excluding vendor/node_modules)"
echo

# ---------------------------------------------------------------------------
# 2. Portable tool bootstrap (fetch into bin/ if missing and allowed)
# ---------------------------------------------------------------------------
# Resolve a usable semgrep: prefer system install, else our fetched binary.
SEMGREP_CMD=""
if have semgrep; then
  SEMGREP_CMD="semgrep"
elif [ -x "$SEMGREP_BIN" ]; then
  SEMGREP_CMD="$SEMGREP_BIN"
fi

# Write the small wrapper that the rest of the script calls as "$SEMGREP_BIN".
_write_semgrep_wrapper() {
  # $1 = absolute path to the real semgrep executable
  cat > "$SEMGREP_BIN" <<EOF
#!/usr/bin/env bash
exec "$1" "\$@"
EOF
  chmod +x "$SEMGREP_BIN"
  SEMGREP_CMD="$SEMGREP_BIN"
}

# Fetch the standalone 'uv' binary into bin/ (no system Python packages needed).
# uv manages its own isolated Python + tools, which sidesteps Ubuntu's missing
# python3-venv / externally-managed-environment (PEP 668) problems entirely.
_fetch_uv() {
  [ -x "$BIN_DIR/uv" ] && { echo "$BIN_DIR/uv"; return 0; }
  local uv_target=""
  case "$OS/$ARCH" in
    Linux/x86_64)  uv_target="x86_64-unknown-linux-gnu" ;;
    Linux/arm64)   uv_target="aarch64-unknown-linux-gnu" ;;
    Darwin/x86_64) uv_target="x86_64-apple-darwin" ;;
    Darwin/arm64)  uv_target="aarch64-apple-darwin" ;;
    *) return 1 ;;
  esac
  local url="https://github.com/astral-sh/uv/releases/latest/download/uv-${uv_target}.tar.gz"
  local tmp="$BIN_DIR/uv-dl.tar.gz"
  if have curl; then curl -fsSL -o "$tmp" "$url" 2>/dev/null
  elif have wget; then wget -q -O "$tmp" "$url" 2>/dev/null
  else return 1; fi
  [ -s "$tmp" ] || return 1
  tar xzf "$tmp" -C "$BIN_DIR" 2>/dev/null || return 1
  # Archive extracts to a folder like uv-<target>/uv ; find and hoist it.
  local found
  found="$(find "$BIN_DIR" -maxdepth 2 -type f -name uv 2>/dev/null | head -1)"
  [ -n "$found" ] || return 1
  [ "$found" = "$BIN_DIR/uv" ] || cp "$found" "$BIN_DIR/uv"
  chmod +x "$BIN_DIR/uv"
  rm -f "$tmp"
  echo "$BIN_DIR/uv"
}

fetch_semgrep() {
  [ "$ALLOW_FETCH" = "yes" ] || { warn "Semgrep missing and --no-fetch set; skipping."; return 1; }
  [ "$INTERNET" = "yes" ]    || { warn "Semgrep missing and no internet; skipping."; return 1; }

  # Strategy 1: pipx already on the system (cleanest when present).
  if have pipx; then
    log "Installing Semgrep via pipx (first run only)..."
    if PIPX_HOME="$BIN_DIR/pipx" PIPX_BIN_DIR="$BIN_DIR/pipx-bin" pipx install semgrep >>"$RAW_DIR/semgrep-install.log" 2>&1 \
       && [ -x "$BIN_DIR/pipx-bin/semgrep" ]; then
      _write_semgrep_wrapper "$BIN_DIR/pipx-bin/semgrep"; ok "Semgrep installed via pipx."; return 0
    fi
    warn "pipx install failed (see raw/semgrep-install.log); trying uv."
  fi

  # Strategy 2: standalone 'uv' binary — no system Python packages required.
  log "Installing Semgrep via uv (first run only; downloads a small static tool)..."
  local uv
  if uv="$(_fetch_uv)"; then
    # uv tool install puts the executable under a tools dir; point UV at bin/.
    if UV_TOOL_DIR="$BIN_DIR/uv-tools" UV_TOOL_BIN_DIR="$BIN_DIR/uv-bin" \
         "$uv" tool install semgrep >>"$RAW_DIR/semgrep-install.log" 2>&1 \
       && [ -x "$BIN_DIR/uv-bin/semgrep" ]; then
      _write_semgrep_wrapper "$BIN_DIR/uv-bin/semgrep"; ok "Semgrep installed via uv."; return 0
    fi
    warn "uv install failed (see raw/semgrep-install.log); trying python venv."
  else
    warn "Could not fetch uv; trying python venv."
  fi

  # Strategy 3: python venv + pip (works only if python3-venv is present).
  if have python3 && python3 -m venv "$BIN_DIR/semgrep-venv" >>"$RAW_DIR/semgrep-install.log" 2>&1 \
     && "$BIN_DIR/semgrep-venv/bin/pip" install --quiet --upgrade pip semgrep >>"$RAW_DIR/semgrep-install.log" 2>&1; then
    _write_semgrep_wrapper "$BIN_DIR/semgrep-venv/bin/semgrep"; ok "Semgrep installed via python venv."; return 0
  fi

  warn "All Semgrep install methods failed (see raw/semgrep-install.log). Relying on built-in checks."
  warn "Tip: 'sudo apt-get install -y python3-venv' (or pipx) enables the deep code scan."
  return 1
}

if [ -z "$SEMGREP_CMD" ]; then
  fetch_semgrep || true
fi

fetch_wp_cli() {
  [ "$IS_WORDPRESS" = "yes" ] || return 1
  have wp && return 0                       # system wp-cli present
  [ -f "$WP_CLI_PHAR" ] && return 0         # already fetched
  [ "$ALLOW_FETCH" = "yes" ] || return 1
  [ "$INTERNET" = "yes" ]    || return 1
  have php || return 1
  log "Fetching wp-cli into bin/ (first run only)..."
  if have curl; then
    curl -fsSL -o "$WP_CLI_PHAR" https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar 2>/dev/null
  elif have wget; then
    wget -q -O "$WP_CLI_PHAR" https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar 2>/dev/null
  fi
  [ -s "$WP_CLI_PHAR" ] && { ok "wp-cli fetched."; return 0; } || { warn "wp-cli fetch failed."; return 1; }
}

# Resolve a wp-cli invocation (system 'wp' or our phar via php)
WP_CMD=""
if [ "$IS_WORDPRESS" = "yes" ]; then
  fetch_wp_cli || true
  if have wp; then
    WP_CMD="wp"
  elif [ -f "$WP_CLI_PHAR" ] && have php; then
    WP_CMD="php $WP_CLI_PHAR"
  fi
fi

echo

# ---------------------------------------------------------------------------
# 3. Dependency vulnerability scan (composer audit)
# ---------------------------------------------------------------------------
if [ "$IS_COMPOSER" = "yes" ]; then
  if have composer; then
    log "Running dependency vulnerability scan (composer audit)..."
    # JSON output lets us emit one finding per advisory with real severity.
    composer audit --working-dir="$TARGET" --format=json > "$RAW_DIR/composer-audit.json" 2>/dev/null || true
    composer audit --working-dir="$TARGET" --format=plain > "$RAW_DIR/composer-audit.txt" 2>&1 || true
    if [ -s "$RAW_DIR/composer-audit.json" ] && have php; then
      if php "$LIB_DIR/parse_composer.php" "$RAW_DIR/composer-audit.json" >> "$JSON_FINDINGS" 2>>"$RAW_DIR/composer.log"; then
        ok "Dependency advisories parsed into findings."
      else
        warn "Could not parse composer JSON; see raw/composer-audit.txt."
      fi
    else
      ok "No dependency advisories (or composer produced no JSON)."
    fi
  else
    warn "Composer project found but 'composer' is not installed; skipping dependency scan."
    add_finding "info" "Coverage gap" \
      "Dependency scan skipped (composer not installed)" \
      "This is a Composer-based project, but the 'composer' tool is not available on this server, so third-party libraries were not checked for known vulnerabilities." \
      "composer.json" "" \
      "Install Composer (or run this scan where Composer is available) to enable dependency CVE checks." \
      "scanner"
  fi
  echo
fi

# ---------------------------------------------------------------------------
# 4. Semgrep source-code scan
# ---------------------------------------------------------------------------
if [ -n "$SEMGREP_CMD" ]; then
  log "Running Semgrep security rules (this can take a few minutes)..."
  if $SEMGREP_CMD \
       --config p/php --config p/security-audit \
       --config p/owasp-top-ten --config p/secrets --config p/xss \
       --json --output "$RAW_DIR/semgrep.json" "$TARGET" >/dev/null 2>"$RAW_DIR/semgrep.log"; then
    ok "Semgrep completed."
  else
    warn "Semgrep finished with warnings (see raw/semgrep.log); parsing what it produced."
  fi
  if have php && [ -s "$RAW_DIR/semgrep.json" ]; then
    if php "$LIB_DIR/parse_semgrep.php" "$RAW_DIR/semgrep.json" >> "$JSON_FINDINGS" 2>>"$RAW_DIR/semgrep.log"; then
      ok "Semgrep findings added to report."
    else
      warn "Could not parse Semgrep JSON (see raw/semgrep.log)."
    fi
  fi
  echo
else
  warn "Semgrep unavailable; relying on built-in pattern checks (lower confidence)."
  add_finding "info" "Coverage note" \
    "Primary code scanner (Semgrep) was not available" \
    "The main source-code scanner could not run on this server, so results come from the built-in fallback pattern checks. These catch obvious issues but are less thorough than Semgrep." \
    "" "" \
    "Re-run on a host with internet access (or pre-bundle the Semgrep binary) for a full code scan." \
    "scanner"
  echo
fi

# ---------------------------------------------------------------------------
# 4b. Secrets scan (gitleaks) — real leaked-credential detection
# ---------------------------------------------------------------------------
GITLEAKS_BIN="$BIN_DIR/gitleaks"
_fetch_gitleaks() {
  [ -x "$GITLEAKS_BIN" ] && return 0
  [ "$ALLOW_FETCH" = "yes" ] || return 1
  [ "$INTERNET" = "yes" ]    || return 1
  have curl || return 1
  local gl_os gl_arch
  case "$OS" in Linux) gl_os="linux" ;; Darwin) gl_os="darwin" ;; *) return 1 ;; esac
  case "$ARCH" in x86_64) gl_arch="x64" ;; arm64) gl_arch="arm64" ;; *) return 1 ;; esac

  # Resolve the actual latest release asset URL via the GitHub API (robust;
  # no hardcoded version that can 404). Fall back to a known-good version.
  local api="https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
  local url=""
  url="$(curl -fsSL "$api" 2>/dev/null \
        | grep -oE '"browser_download_url": *"[^"]*"' \
        | sed -E 's/.*"(https[^"]+)".*/\1/' \
        | grep -E "_${gl_os}_${gl_arch}\.tar\.gz$" \
        | head -1)"
  if [ -z "$url" ]; then
    # Fallback: try a recent tagged release directly.
    local v="8.21.2"
    url="https://github.com/gitleaks/gitleaks/releases/download/v${v}/gitleaks_${v}_${gl_os}_${gl_arch}.tar.gz"
  fi

  local tmp="$BIN_DIR/gitleaks-dl.tar.gz"
  curl -fsSL -o "$tmp" "$url" 2>>"$RAW_DIR/gitleaks.log" || return 1
  [ -s "$tmp" ] || return 1
  tar xzf "$tmp" -C "$BIN_DIR" gitleaks 2>/dev/null || tar xzf "$tmp" -C "$BIN_DIR" 2>/dev/null
  rm -f "$tmp"
  [ -f "$BIN_DIR/gitleaks" ] && chmod +x "$BIN_DIR/gitleaks" && return 0
  return 1
}

log "Running secrets scan (gitleaks)..."
if [ ! -x "$GITLEAKS_BIN" ]; then _fetch_gitleaks || true; fi
if [ -x "$GITLEAKS_BIN" ]; then
  # Write a gitleaks config that extends the default rules but allowlists
  # runtime/non-source paths. Without this, framework session stores
  # (e.g. CodeIgniter ci_sessions/ holding JWTs), vendor test fixtures, and
  # build assets produce thousands of false positives.
  GITLEAKS_CFG="$CACHE_DIR/gitleaks.toml"
  cat > "$GITLEAKS_CFG" <<'TOML'
[extend]
useDefault = true

[allowlist]
description = "Exclude runtime, vendor, and non-source paths from secret scanning"
paths = [
  '''(^|/)vendor/''',
  '''(^|/)node_modules/''',
  '''(^|/)\.git/''',
  '''(^|/)ci_sessions/''',
  '''(^|/)sessions?/''',
  '''(^|/)cache/''',
  '''(^|/)writable/''',
  '''(^|/)logs?/''',
  '''(^|/)tmp/''',
  '''(^|/)storage/''',
  '''\.(min\.js|js\.map|css|map|lock|log)$''',
]
TOML
  # 'detect --no-git' scans the filesystem (not git history), read-only.
  "$GITLEAKS_BIN" detect --source "$TARGET" --no-git -c "$GITLEAKS_CFG" \
    --report-format json --report-path "$RAW_DIR/gitleaks.json" \
    --exit-code 0 >/dev/null 2>"$RAW_DIR/gitleaks.log" || true
  if have php && [ -s "$RAW_DIR/gitleaks.json" ]; then
    php "$LIB_DIR/parse_gitleaks.php" "$RAW_DIR/gitleaks.json" "$TARGET" >> "$JSON_FINDINGS" 2>>"$RAW_DIR/gitleaks.log" \
      && ok "Secrets scan parsed." || warn "Could not parse gitleaks output."
  else
    ok "Secrets scan complete (no findings file or php missing)."
  fi
else
  warn "gitleaks unavailable; the built-in secret pattern check will cover this (weaker)."
fi
echo

# ---------------------------------------------------------------------------
# 5. Built-in pattern checks (always run — offline safety net / fallback)
# ---------------------------------------------------------------------------
log "Running built-in code pattern checks..."

scan_pattern() {
  local sev="$1" cat="$2" title="$3" desc="$4" rec="$5" regex="$6"
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    local f="${hit%%:*}"; local rest="${hit#*:}"; local ln="${rest%%:*}"
    local rel="${f#"$TARGET"/}"
    add_finding "$sev" "$cat" "$title" "$desc" "$rel" "$ln" "$rec" "built-in pattern"
  done < <(grep -rInE "$regex" "$TARGET" \
             --include='*.php' --exclude-dir=vendor --exclude-dir=node_modules --exclude-dir=.git \
             2>/dev/null | head -n 200)
}

scan_pattern "critical" "Code execution" \
  "Use of eval() — runs text as live code" \
  "The code uses eval(), which executes a string as if it were program code. If any part of that string can be influenced by a visitor, an attacker could make the server run their own commands." \
  "Avoid eval() entirely. Replace it with explicit logic; if unavoidable, ensure the input is a fixed, trusted value." \
  '(^|[^a-zA-Z0-9_])eval[[:space:]]*\('

scan_pattern "high" "Command execution" \
  "Running operating-system commands (system/exec/shell_exec/passthru)" \
  "The code can run commands directly on the server's operating system. If visitor-supplied data reaches these commands, an attacker could take control of the server." \
  "Avoid shelling out. If required, use escapeshellarg()/escapeshellcmd() and never pass raw user input." \
  '(^|[^a-zA-Z0-9_])(system|exec|shell_exec|passthru|popen|proc_open)[[:space:]]*\('

scan_pattern "high" "SQL injection" \
  "Database query appears to include request data directly" \
  "A database query seems to be built by pasting in values that came from the visitor (\$_GET/\$_POST/\$_REQUEST). This is the classic cause of SQL injection, where an attacker can read or change the database." \
  "Use prepared statements / parameterised queries (PDO or mysqli with bound parameters) instead of inserting values into the query text." \
  '(SELECT|INSERT|UPDATE|DELETE).*\$_(GET|POST|REQUEST)'

scan_pattern "medium" "Cross-site scripting (XSS)" \
  "Request data echoed to the page without escaping" \
  "The page prints data that came straight from the visitor without cleaning it. An attacker could inject scripts that run in other users' browsers (XSS)." \
  "Escape output with htmlspecialchars() (or the framework's escaping) before printing user-controlled data." \
  'echo[[:space:]]+\$_(GET|POST|REQUEST|COOKIE)'

scan_pattern "high" "File inclusion" \
  "Including a file whose name comes from the request" \
  "The code loads a file whose path is partly controlled by the visitor. Attackers can abuse this to load unintended files or remote code." \
  "Never build include/require paths from user input. Use a fixed allow-list of filenames." \
  '(include|require)(_once)?[[:space:]]*\(?[[:space:]]*\$_(GET|POST|REQUEST)'

scan_pattern "high" "Insecure deserialization" \
  "unserialize() on request data" \
  "The code turns visitor-supplied text back into PHP objects. Crafted input here can trigger hidden code paths (object injection)." \
  "Avoid unserialize() on untrusted data; use json_decode(), or pass allowed_classes => false." \
  'unserialize[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)'

# Weak-crypto rule intentionally narrowed: only flag md5/sha1 when used
# directly on a password-like variable. The blanket md5()/sha1() rule produced
# overwhelming false positives (cache keys, ETags, file hashes) in frameworks.
# Semgrep covers contextual crypto misuse properly when available.
scan_pattern "medium" "Weak cryptography" \
  "md5()/sha1() used on a password value" \
  "A password value appears to be hashed with md5 or sha1, which are too weak for passwords and can be cracked quickly." \
  "Use password_hash()/password_verify() for passwords." \
  '(md5|sha1)[[:space:]]*\([^)]*(pass|pwd|passwd|password)'

# Note: the regex "hardcoded secret" rule was removed — gitleaks (above) does
# this far better with entropy + known-token patterns, so this would only add noise.

ok "Built-in pattern checks complete."
echo

# ---------------------------------------------------------------------------
# 5b. PHP runtime configuration hardening check (php.ini directives)
# ---------------------------------------------------------------------------
if have php; then
  log "Checking PHP runtime configuration (php.ini hardening)..."
  # Read effective values from the CLI runtime. (Note: web SAPI may differ;
  # the report says so.) Each risky directive becomes a finding.
  check_ini() {
    local directive="$1" badval="$2" sev="$3" title="$4" desc="$5" rec="$6"
    local val
    val="$(php -r "echo ini_get('$directive');" 2>/dev/null)"
    # Normalise booleans PHP may report as "" / "0" / "1" / "On"
    local norm
    norm="$(printf '%s' "$val" | tr '[:upper:]' '[:lower:]')"
    if [ "$badval" = "on" ] && { [ "$norm" = "1" ] || [ "$norm" = "on" ] || [ "$norm" = "true" ]; }; then
      add_finding "$sev" "PHP configuration" "$title" "$desc (current value: '${val}')" "php.ini ($directive)" "" "$rec" "runtime config check"
    elif [ "$badval" = "nonempty" ] && [ -n "$val" ]; then
      add_finding "$sev" "PHP configuration" "$title" "$desc (current value: '${val}')" "php.ini ($directive)" "" "$rec" "runtime config check"
    fi
  }
  check_ini "display_errors" "on" "medium" \
    "display_errors is On" \
    "PHP is configured to show errors to visitors, which can leak file paths, queries, and internal details useful to an attacker." \
    "Set display_errors = Off in production; log errors to a file (log_errors = On) instead."
  check_ini "allow_url_include" "on" "high" \
    "allow_url_include is On" \
    "PHP is allowed to include files from remote URLs, which turns a file-inclusion bug into remote code execution." \
    "Set allow_url_include = Off."
  check_ini "allow_url_fopen" "on" "low" \
    "allow_url_fopen is On" \
    "PHP can open remote URLs as files. Often needed, but it widens SSRF/file-inclusion risk." \
    "Disable if the application does not need to fetch remote URLs via file functions."
  check_ini "expose_php" "on" "low" \
    "expose_php is On" \
    "PHP advertises its presence and version in HTTP headers, helping attackers target version-specific exploits." \
    "Set expose_php = Off."
  check_ini "enable_dl" "on" "medium" \
    "enable_dl is On" \
    "Dynamic loading of PHP extensions is enabled, which can be abused to bypass restrictions." \
    "Set enable_dl = Off."
  # Dangerous functions that should usually be disabled in production.
  disabled="$(php -r "echo ini_get('disable_functions');" 2>/dev/null)"
  for fn in exec shell_exec system passthru proc_open popen; do
    case ",$disabled," in
      *",$fn,"*) : ;;  # already disabled, good
      *) : ;;          # (informational only — many apps legitimately need some)
    esac
  done
  ok "PHP configuration check complete."
  echo
fi

# ---------------------------------------------------------------------------
# 6. WordPress-specific checks
# ---------------------------------------------------------------------------
if [ "$IS_WORDPRESS" = "yes" ]; then
  log "Running WordPress-specific checks..."

  if [ -f "$TARGET/wp-config.php" ]; then
    perms="$(stat -f '%Lp' "$TARGET/wp-config.php" 2>/dev/null || stat -c '%a' "$TARGET/wp-config.php" 2>/dev/null || echo '')"
    if [ -n "$perms" ] && [ "$perms" -gt 640 ] 2>/dev/null; then
      add_finding "medium" "WordPress config" \
        "wp-config.php is readable by others (permissions $perms)" \
        "The main WordPress configuration file, which holds the database password and secret keys, can be read more widely than it should be." \
        "wp-config.php" "" \
        "Restrict permissions to 640 or stricter (chmod 640 wp-config.php) and ensure the web user owns it." \
        "built-in config check"
    fi
    if grep -q "put your unique phrase here" "$TARGET/wp-config.php" 2>/dev/null; then
      add_finding "high" "WordPress config" \
        "Default WordPress security keys (salts) not changed" \
        "The secret 'salts' in wp-config.php still look like the default placeholders. These keys protect login sessions." \
        "wp-config.php" "" \
        "Generate fresh keys at https://api.wordpress.org/secret-key/1.1/salt/ and paste them into wp-config.php." \
        "built-in config check"
    fi
  fi

  if [ -f "$TARGET/xmlrpc.php" ]; then
    add_finding "low" "WordPress" \
      "xmlrpc.php is present and may be reachable" \
      "xmlrpc.php is a legacy WordPress interface often abused for brute-force login attempts and denial-of-service amplification. Many sites do not need it." \
      "xmlrpc.php" "" \
      "If the site does not use XML-RPC, block or disable access to xmlrpc.php at the web server or via a security plugin." \
      "built-in config check"
  fi

  if [ -f "$TARGET/readme.html" ]; then
    add_finding "low" "WordPress" \
      "readme.html exposes the WordPress version" \
      "The default readme.html reveals which WordPress version is installed, helping attackers pick matching exploits." \
      "readme.html" "" \
      "Delete or block access to readme.html." \
      "built-in config check"
  fi

  # Inventory via wp-cli (system or fetched phar)
  if [ -n "$WP_CMD" ]; then
    ok "Collecting WordPress inventory via wp-cli..."
    # --allow-root in case the scan runs as root; --skip-plugins/themes avoids loading app code
    $WP_CMD --path="$TARGET" --allow-root --skip-plugins --skip-themes core version \
      > "$RAW_DIR/wp-core-version.txt" 2>/dev/null || true
    $WP_CMD --path="$TARGET" --allow-root --skip-plugins --skip-themes plugin list --fields=name,status,version --format=csv \
      > "$RAW_DIR/wp-plugins.csv" 2>/dev/null || true
    $WP_CMD --path="$TARGET" --allow-root --skip-plugins --skip-themes theme list --fields=name,status,version --format=csv \
      > "$RAW_DIR/wp-themes.csv" 2>/dev/null || true
  else
    warn "wp-cli unavailable; reading versions from files directly."
    # Fallback: read core version from version.php
    if [ -f "$TARGET/wp-includes/version.php" ]; then
      wpver="$(grep -oE "\\\$wp_version = '[^']+'" "$TARGET/wp-includes/version.php" 2>/dev/null | head -1 | grep -oE "'[^']+'" | tr -d "'")"
      [ -n "$wpver" ] && printf 'wordpress-core,active,%s\n' "$wpver" > "$RAW_DIR/wp-core-fallback.csv"
    fi
  fi

  # Wordfence feed: fetch (cached) and match installed versions
  if [ ! -s "$WORDFENCE_FEED" ] && [ "$ALLOW_FETCH" = "yes" ] && [ "$INTERNET" = "yes" ]; then
    log "Fetching Wordfence Intelligence vulnerability feed (cached for reuse)..."
    AUTH=()
    [ -n "${WORDFENCE_API_KEY:-}" ] && AUTH=(-u "$WORDFENCE_API_KEY:")
    if have curl; then
      curl -fsSL "${AUTH[@]}" -o "$WORDFENCE_FEED" "$WORDFENCE_URL" 2>/dev/null || true
    fi
    [ -s "$WORDFENCE_FEED" ] && ok "Wordfence feed cached." || warn "Could not fetch Wordfence feed (set WORDFENCE_API_KEY if required)."
  fi

  if [ -s "$WORDFENCE_FEED" ] && have php; then
    log "Matching installed plugins/themes against the Wordfence feed..."
    php "$LIB_DIR/match_wordfence.php" "$WORDFENCE_FEED" "$RAW_DIR" >> "$JSON_FINDINGS" 2>>"$RAW_DIR/wordfence.log" \
      && ok "Wordfence matching complete." \
      || warn "Wordfence matching had problems (see raw/wordfence.log)."
  else
    add_finding "info" "Coverage gap" \
      "WordPress CVE matching skipped (no Wordfence feed available)" \
      "The Wordfence vulnerability feed was not available (offline, or no API key), so installed plugins/themes were not matched against known WordPress CVEs." \
      "" "" \
      "Provide internet access and WORDFENCE_API_KEY, or pre-bundle cache/wordfence-vulns.json, to enable WordPress CVE matching." \
      "scanner"
  fi

  ok "WordPress checks complete."
  echo
fi

# ---------------------------------------------------------------------------
# 7. Build reports (HTML + JSON)
# ---------------------------------------------------------------------------
log "Building reports..."

export SCAN_TARGET="$TARGET"
export SCAN_APP_TYPE="$APP_TYPE"
export SCAN_PHP_VERSION="$PHP_VERSION"
export SCAN_INTERNET="$INTERNET"
export SCAN_PHP_FILES="$PHP_FILE_COUNT"
export SCAN_PLATFORM="$OS/$ARCH"
export SCAN_STAMP="$STAMP"
export SCAN_SEMGREP="$( [ -n "$SEMGREP_CMD" ] && echo yes || echo no )"
export SCAN_MIN_SEVERITY="$MIN_SEVERITY"
export SCAN_HOSTNAME="$HOSTNAME_FULL"
export SCAN_HOST_IP="$HOST_IP"
export SCAN_EC2_INSTANCE_ID="$EC2_INSTANCE_ID"
export SCAN_EC2_REGION="$EC2_REGION"
export SCAN_REPORT_NAME="$REPORT_NAME"

if have php; then
  php "$LIB_DIR/build_report.php" "$JSON_FINDINGS" "$OUT_DIR" \
    && ok "Reports written." \
    || warn "Report builder failed; raw findings are in $JSON_FINDINGS"
else
  warn "PHP is not installed, so the HTML report cannot be built."
  warn "Raw findings (one JSON object per line) are in: $JSON_FINDINGS"
fi

# ---------------------------------------------------------------------------
# 8. Optional: upload the report to S3 (uses instance IAM role; no keys needed)
# ---------------------------------------------------------------------------
if [ -n "$S3_DEST" ]; then
  echo
  if have aws; then
    dest="${S3_DEST%/}/$REPORT_NAME/"
    log "Uploading report to $dest ..."
    if aws s3 cp "$OUT_DIR/report.html" "$dest" >/dev/null 2>"$RAW_DIR/s3.log" \
       && aws s3 cp "$OUT_DIR/report.json" "$dest" >/dev/null 2>>"$RAW_DIR/s3.log"; then
      ok "Report uploaded to $dest"
    else
      warn "S3 upload failed (see raw/s3.log). Check the instance IAM role has s3:PutObject on the bucket."
    fi
  else
    warn "--s3 given but the AWS CLI is not installed; skipping upload. Report is still on disk."
  fi
fi

echo
echo "${C_BOLD}Done.${C_OFF}"
echo "  Host         : $HOSTNAME_FULL ($HOST_IP)${EC2_INSTANCE_ID:+  [$EC2_INSTANCE_ID / $EC2_REGION]}"
echo "  Report name  : $REPORT_NAME"
echo "  Human report : $OUT_DIR/report.html"
echo "  Data report  : $OUT_DIR/report.json"
echo "  Raw tool logs: $RAW_DIR/"
[ -n "$S3_DEST" ] && echo "  S3 target    : ${S3_DEST%/}/$REPORT_NAME/"
echo "  (Run './scan.sh --cleanup' to remove fetched tools, keeping reports.)"
echo
