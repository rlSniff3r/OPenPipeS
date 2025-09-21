#!/usr/bin/env bash
# installer.sh - OPenPipeS installer (robusto, idempotente, opinionated)
# Author: ChatGPT (assistente)
# Purpose: install and configure dependencies for OPenPipeS repo
# Usage:
#   sudo ./installer.sh [--yes] [--dry-run] [--skip-go] [--skip-amass] [--skip-dnsrecon] [--skip-httpx] [--skip-nuclei] [--skip-nuclei-templates] [--skip-ferox] [--skip-katana] [--skip-gf] [--skip-jq] [--install-all]
#
# Examples:
#   sudo ./installer.sh --yes
#   ./installer.sh --dry-run --skip-nuclei
#
set -euo pipefail
IFS=$'\n\t'

### -------------------------
### CONFIGURABLE VERSIONS
### -------------------------
AMASS_VERSION="3.20.0"
DNSRECON_VERSION="1.1.3"

# pinned go installs (use module@version if desired)
HTTPX_GO_PKG="github.com/projectdiscovery/httpx/cmd/httpx@latest"
NUCLEI_GO_PKG="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
FEROX_GO_PKG="github.com/epi052/feroxbuster@latest"      # note: feroxbuster also available as binary
KATANA_GO_PKG="github.com/projectdiscovery/katana/cmd/katana@latest"
GF_REPO="https://github.com/tomnomnom/gf"
GF_PATTERNS_REPO="https://github.com/1ndianl33t/Gf-Patterns"

# Install directories & paths
BIN_DIR="/usr/local/bin"
OPENPIPES_DIR="$(pwd)"
OPENPIPES_CONFIG_DIR="${OPENPIPES_DIR}/.openpipes"
OPENPIPES_CONFIG_FILE="${OPENPIPES_CONFIG_DIR}/config.sh"
CACHE_DIR="${OPENPIPES_DIR}/.openpipes_cache"

# flags (default)
DRY_RUN=0
AUTO_YES=0
SKIP_GO=0
SKIP_AMASS=0
SKIP_DNSRECON=0
SKIP_HTTPX=0
SKIP_NUCLEI=0
SKIP_NUCLEI_TEMPLATES=0
SKIP_FEROX=0
SKIP_KATANA=0
SKIP_GF=0
SKIP_JQ=0
INSTALL_ALL=0

### -------------------------
### COLORS & UTILS
### -------------------------
info()    { printf "\e[1;34m[INFO]\e[0m %s\n" "$*"; }
ok()      { printf "\e[1;32m[ OK ]\e[0m %s\n" "$*"; }
warn()    { printf "\e[1;33m[WARN]\e[0m %s\n" "$*"; }
err()     { printf "\e[1;31m[ERR ]\e[0m %s\n" "$*"; }
run()     { if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: %s\n" "$*"; else eval "$*"; fi; }

usage() {
  cat <<EOF
OPenPipeS installer - usage

sudo ./installer.sh [options]

Options:
  --yes                      Non-interactive; answer yes to prompts
  --dry-run                  Show actions without executing (safe)
  --install-all              Try to install everything (default unless using skips)
  --skip-go                  Skip Go toolchain install
  --skip-amass               Skip amass install
  --skip-dnsrecon            Skip dnsrecon install
  --skip-httpx               Skip httpx install
  --skip-nuclei              Skip nuclei install
  --skip-nuclei-templates    Skip fetching nuclei-templates
  --skip-ferox               Skip feroxbuster install
  --skip-katana              Skip katana install
  --skip-gf                  Skip gf and patterns install
  --skip-jq                  Skip jq install (some scripts use it)
  -h, --help                 Show this help

EOF
  exit 1
}

### -------------------------
### PARSE ARGS
### -------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --yes) AUTO_YES=1; shift ;;
    --skip-go) SKIP_GO=1; shift ;;
    --skip-amass) SKIP_AMASS=1; shift ;;
    --skip-dnsrecon) SKIP_DNSRECON=1; shift ;;
    --skip-httpx) SKIP_HTTPX=1; shift ;;
    --skip-nuclei) SKIP_NUCLEI=1; shift ;;
    --skip-nuclei-templates) SKIP_NUCLEI_TEMPLATES=1; shift ;;
    --skip-ferox) SKIP_FEROX=1; shift ;;
    --skip-katana) SKIP_KATANA=1; shift ;;
    --skip-gf) SKIP_GF=1; shift ;;
    --skip-jq) SKIP_JQ=1; shift ;;
    --install-all) INSTALL_ALL=1; shift ;;
    -h|--help) usage ;;
    *) warn "Unknown option: $1"; usage ;;
  esac
done

if [ "$INSTALL_ALL" -eq 1 ]; then
  SKIP_GO=0; SKIP_AMASS=0; SKIP_DNSRECON=0; SKIP_HTTPX=0; SKIP_NUCLEI=0; SKIP_NUCLEI_TEMPLATES=0; SKIP_FEROX=0; SKIP_KATANA=0; SKIP_GF=0; SKIP_JQ=0
fi

confirm() {
  local prompt="$1"
  if [ "$AUTO_YES" -eq 1 ]; then return 0; fi
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: would ask: %s\n" "$prompt"; return 0; fi
  read -rp "$prompt [y/N]: " ans
  case "$ans" in
    [Yy]* ) return 0 ;;
    * ) return 1 ;;
  esac
}

### -------------------------
### SIMPLE OS DETECTION
### -------------------------
OS=""
PKG=""
if [ "$(uname -s)" = "Darwin" ]; then
  OS="macos"
  PKG="brew"
else
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "${ID_LIKE:-$ID}" in
      *debian*|*ubuntu*|debian|ubuntu) OS="debian"; PKG="apt-get" ;;
      *rhel*|*fedora*|rhel|fedora|centos) OS="rhel"; PKG="yum" ;;
      *) OS="linux"; PKG="apt-get" ;;
    esac
  else
    OS="linux"
    PKG="apt-get"
  fi
fi
info "Detected OS: $OS (pkg: $PKG)"

### -------------------------
### HELPERS
### -------------------------
backup_if_exists() {
  local file="$1"
  if [ -e "$file" ]; then
    local stamp
    stamp="$(date +%Y%m%d_%H%M%S)"
    local dest="${file}.orig_${stamp}"
    info "Backing up existing '$file' -> '$dest'"
    run "sudo cp -a \"$file\" \"$dest\""
  fi
}

ensure_dir() {
  local dir="$1"
  if [ ! -d "$dir" ]; then
    info "Creating $dir"
    run "mkdir -p \"$dir\""
  fi
}

install_pkg() {
  local pkgname="$1"
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: would install package %s\n" "$pkgname"; return; fi

  case "$PKG" in
    apt-get)
      if ! command -v apt-get >/dev/null 2>&1; then err "apt-get not found"; return 1; fi
      sudo apt-get update -y
      sudo apt-get install -y "$pkgname"
      ;;
    yum)
      sudo yum install -y "$pkgname"
      ;;
    brew)
      brew install "$pkgname"
      ;;
    *)
      warn "Unknown package manager: $PKG - try installing $pkgname manually"
      return 1
      ;;
  esac
}

install_snap_if_missing() {
  # some systems may use snap for certain packages (left optional)
  true
}

install_go() {
  if [ "$SKIP_GO" -eq 1 ]; then info "Skipping Go install (flag)"; return 0; fi
  if command -v go >/dev/null 2>&1; then
    ok "Go already installed: $(go version)"
    return 0
  fi
  info "Installing Go (if possible)..."
  case "$OS" in
    debian)
      install_pkg "golang-go"
      ;;
    rhel)
      install_pkg "golang"
      ;;
    macos)
      install_pkg "go"
      ;;
    *)
      warn "Unable to install Go automatically for OS=$OS; please install go >= 1.18 manually."
      ;;
  esac
  if command -v go >/dev/null 2>&1; then ok "Go installed: $(go version)"; else warn "Go not installed or not in PATH."
  fi
}

install_jq() {
  if [ "$SKIP_JQ" -eq 1 ]; then info "Skipping jq (flag)"; return 0; fi
  if command -v jq >/dev/null 2>&1; then ok "jq exists: $(jq --version)"; return 0; fi
  info "Installing jq..."
  case "$PKG" in
    apt-get) install_pkg "jq" ;;
    yum) install_pkg "jq" || install_pkg "epel-release" && install_pkg "jq" ;;
    brew) install_pkg "jq" ;;
    *) warn "Please install jq manually." ;;
  esac
}

install_basic_utils() {
  # common utilities used by scripts
  info "Ensuring basic utilities (curl, wget, unzip, git, python3) are present..."
  PKGS=(curl wget unzip git python3 python3-pip ca-certificates)
  for p in "${PKGS[@]}"; do
    if ! command -v "$p" >/dev/null 2>&1; then
      warn "Package $p not found - attempting to install via package manager"
      install_pkg "$p" || warn "Failed to install $p automatically"
    else
      ok "$p present"
    fi
  done
}

download_and_extract() {
  local url="$1"; local dest_dir="$2"; local strip_root="${3:-1}"
  ensure_dir "$dest_dir"
  local tmp
  tmp="$(mktemp -d)"
  run "curl -L --fail -o \"$tmp/archive\" \"$url\""
  run "unzip -o \"$tmp/archive\" -d \"$tmp/extracted\" >/dev/null 2>&1 || tar -xf \"$tmp/archive\" -C \"$tmp/extracted\" >/dev/null 2>&1 || true"
  if [ "$strip_root" -eq 1 ]; then
    # move contents of first subdir into dest_dir
    local first
    first="$(find \"$tmp/extracted\" -maxdepth 1 -mindepth 1 -type d | head -n1 || true)"
    if [ -n "$first" ]; then
      run "cp -r \"$first/\"* \"$dest_dir/\" || true"
    else
      run "cp -r \"$tmp/extracted\"/* \"$dest_dir/\" || true"
    fi
  else
    run "cp -r \"$tmp/extracted\"/* \"$dest_dir/\" || true"
  fi
  run "rm -rf \"$tmp\""
}

install_amass() {
  if [ "$SKIP_AMASS" -eq 1 ]; then info "Skipping amass (flag)"; return 0; fi
  if command -v amass >/dev/null 2>&1; then
    ok "amass exists: $(amass -version 2>&1 | head -n1 || true)"
  fi

  info "Installing amass v${AMASS_VERSION}..."
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) arch="amd64" ;;
  esac

  local tmp_url="https://github.com/OWASP/Amass/releases/download/v${AMASS_VERSION}/amass_linux_${arch}.zip"
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: would download %s\n" "$tmp_url"; return 0; fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  info "Downloading $tmp_url..."
  if ! curl -L --fail -o "${tmpdir}/amass.zip" "$tmp_url"; then
    warn "Could not download amass from $tmp_url. You may need to fetch it manually."
  else
    run "unzip -o \"${tmpdir}/amass.zip\" -d \"${tmpdir}\" >/dev/null 2>&1 || true"
    if [ -f "${tmpdir}/amass" ]; then
      backup_if_exists "${BIN_DIR}/amass"
      run "sudo cp -a \"${tmpdir}/amass\" \"${BIN_DIR}/amass\""
      run "sudo chmod +x \"${BIN_DIR}/amass\""
      ok "amass v${AMASS_VERSION} installed to ${BIN_DIR}/amass"
    else
      warn "amass binary not found inside downloaded archive"
    fi
  fi
  run "rm -rf \"$tmpdir\""
}

install_dnsrecon() {
  if [ "$SKIP_DNSRECON" -eq 1 ]; then info "Skipping dnsrecon (flag)"; return 0; fi
  if command -v dnsrecon >/dev/null 2>&1; then
    ok "dnsrecon exists: $(dnsrecon -V 2>&1 || true)"
  fi

  info "Installing dnsrecon v${DNSRECON_VERSION}..."
  local url="https://github.com/darkoperator/dnsrecon/archive/refs/tags/${DNSRECON_VERSION}.zip"
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: would download %s\n" "$url"; return 0; fi

  local tmpdir
  tmpdir="$(mktemp -d)"
  run "curl -L --fail -o \"${tmpdir}/dnsrecon.zip\" \"$url\""
  run "unzip -o \"${tmpdir}/dnsrecon.zip\" -d \"${tmpdir}\" >/dev/null 2>&1 || true"
  # dnsrecon v1.1.3 structure: dnsrecon-1.1.3/dnsrecon.py etc
  local extracted
  extracted="$(find "${tmpdir}" -maxdepth 1 -type d -name 'dnsrecon*' | head -n1)"
  if [ -n "$extracted" ]; then
    # Copy dnsrecon script to /usr/local/bin and make executable
    backup_if_exists "${BIN_DIR}/dnsrecon"
    if [ -f "${extracted}/dnsrecon.py" ]; then
      run "sudo cp -a \"${extracted}/dnsrecon.py\" \"${BIN_DIR}/dnsrecon\""
      run "sudo chmod +x \"${BIN_DIR}/dnsrecon\""
      ok "dnsrecon installed to ${BIN_DIR}/dnsrecon"
    else
      warn "dnsrecon.py not found in archive; you may need to install dnsrecon manually."
    fi
  else
    warn "Could not extract dnsrecon archive; check download URL."
  fi
  run "rm -rf \"$tmpdir\""
}

install_httpx() {
  if [ "$SKIP_HTTPX" -eq 1 ]; then info "Skipping httpx (flag)"; return 0; fi
  if command -v httpx >/dev/null 2>&1; then ok "httpx exists: $(httpx -version 2>&1 || true)"; return 0; fi
  if [ "$SKIP_GO" -eq 1 ]; then warn "Skipping httpx: go not available"; return 1; fi
  info "Installing httpx via 'go install'..."
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: go install %s\n" "$HTTPX_GO_PKG"; return 0; fi
  run "GOBIN=${BIN_DIR} go install ${HTTPX_GO_PKG}"
  ok "httpx installed to ${BIN_DIR}"
}

install_nuclei() {
  if [ "$SKIP_NUCLEI" -eq 1 ]; then info "Skipping nuclei (flag)"; return 0; fi
  if command -v nuclei >/dev/null 2>&1; then ok "nuclei exists: $(nuclei -version 2>&1 || true)"; return 0; fi
  if [ "$SKIP_GO" -eq 1 ]; then warn "Skipping nuclei: go not available"; return 1; fi
  info "Installing nuclei via 'go install'..."
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: go install %s\n" "$NUCLEI_GO_PKG"; return 0; fi
  run "GOBIN=${BIN_DIR} go install ${NUCLEI_GO_PKG}"
  ok "nuclei installed to ${BIN_DIR}"
  if [ "$SKIP_NUCLEI_TEMPLATES" -eq 0 ]; then
    fetch_nuclei_templates
  fi
}

fetch_nuclei_templates() {
  info "Fetching nuclei-templates (git clone/update)..."
  ensure_dir "${OPENPIPES_DIR}/.openpipes_templates"
  if [ -d "${OPENPIPES_DIR}/nuclei-templates" ]; then
    info "Updating existing nuclei-templates..."
    if [ "$DRY_RUN" -eq 0 ]; then
      (cd "${OPENPIPES_DIR}/nuclei-templates" && git pull --rebase || true)
    fi
  else
    run "git clone https://github.com/projectdiscovery/nuclei-templates.git \"${OPENPIPES_DIR}/nuclei-templates\" || true"
  fi
  ok "nuclei-templates is ready (in ${OPENPIPES_DIR}/nuclei-templates)"
}

install_ferox() {
  if [ "$SKIP_FEROX" -eq 1 ]; then info "Skipping feroxbuster (flag)"; return 0; fi
  if command -v feroxbuster >/dev/null 2>&1; then ok "feroxbuster exists: $(feroxbuster -V 2>&1 || true)"; return 0; fi
  if [ "$SKIP_GO" -eq 1 ]; then warn "Skipping feroxbuster: go not available"; return 1; fi
  info "Installing feroxbuster via go install..."
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: go install %s\n" "$FEROX_GO_PKG"; return 0; fi
  run "GOBIN=${BIN_DIR} go install ${FEROX_GO_PKG}"
  ok "feroxbuster installed to ${BIN_DIR}"
}

install_katana() {
  if [ "$SKIP_KATANA" -eq 1 ]; then info "Skipping katana (flag)"; return 0; fi
  if command -v katana >/dev/null 2>&1; then ok "katana exists: $(katana -h >/dev/null 2>&1 || true)"; return 0; fi
  if [ "$SKIP_GO" -eq 1 ]; then warn "Skipping katana: go not available"; return 1; fi
  info "Installing katana via go install..."
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: go install %s\n" "$KATANA_GO_PKG"; return 0; fi
  run "GOBIN=${BIN_DIR} go install ${KATANA_GO_PKG}"
  ok "katana installed to ${BIN_DIR}"
}

install_gf() {
  if [ "$SKIP_GF" -eq 1 ]; then info "Skipping gf (flag)"; return 0; fi
  if command -v gf >/dev/null 2>&1; then ok "gf exists: $(gf -h >/dev/null 2>&1 || true)"; return 0; fi
  info "Installing gf (tomnomnom) and patterns..."
  run "go install github.com/tomnomnom/gf@latest"
  run "GFPATH=\$HOME/.gf && mkdir -p \"\$GFPATH\""
  if [ ! -d "$HOME/.gf" ] || [ ! -f "$HOME/.gf/README.md" ]; then
    run "git clone ${GF_PATTERNS_REPO} /tmp/gf-patterns || true"
    run "cp -r /tmp/gf-patterns/* \$HOME/.gf/ || true"
    run "rm -rf /tmp/gf-patterns || true"
  fi
  ok "gf installed and patterns copied to \$HOME/.gf"
}

install_additional_tools() {
  install_jq
  install_go
  # whois, rdap etc
  for p in whois rdap; do
    if ! command -v "$p" >/dev/null 2>&1; then
      warn "Utility $p not found - attempting to install via package manager"
      install_pkg "$p" || warn "Failed to auto-install $p"
    else
      ok "$p present"
    fi
  done
}

install_nuclei_local_templates() {
  if [ "$SKIP_NUCLEI_TEMPLATES" -eq 1 ]; then info "Skipping nuclei templates (flag)"; return 0; fi
  fetch_nuclei_templates
}

install_kits_and_helpers() {
  # Other small helpers: jsfinder-runner dependencies etc.
  # python packages that scripts reference can be installed here (best-effort)
  if command -v pip3 >/dev/null 2>&1; then
    info "Installing Python helper packages (requests, pyyaml)..."
    run "pip3 install --user requests pyyaml"
  fi
}

write_openpipes_config() {
  ensure_dir "$OPENPIPES_CONFIG_DIR"
  if [ -f "$OPENPIPES_CONFIG_FILE" ]; then
    ok "Config exists: $OPENPIPES_CONFIG_FILE (backing up)"
    backup_if_exists "$OPENPIPES_CONFIG_FILE"
  fi
  if [ "$DRY_RUN" -eq 1 ]; then printf "DRYRUN: would create config at %s\n" "$OPENPIPES_CONFIG_FILE"; return 0; fi

  info "Creating interactive .openpipes/config.sh (will NOT store secrets insecurely if you choose not to)"
  local openai_key=""
  local st_key=""
  local github_token=""
  if [ "$AUTO_YES" -eq 0 ]; then
    read -rp "OpenAI API key (leave empty to skip): " openai_key
    read -rp "SecurityTrails API key (leave empty to skip): " st_key
    read -rp "GitHub token (leave empty to skip): " github_token
  fi

  cat > "$OPENPIPES_CONFIG_FILE" <<EOF
# OPenPipeS configuration (auto-generated)
# Do not commit secrets to git. Edit this file to change settings.
export OPENPIPES_OPENAI_KEY="${openai_key}"
export OPENPIPES_SECURITYTRAILS_KEY="${st_key}"
export OPENPIPES_GITHUB_TOKEN="${github_token}"
# obsdir: location of your Obsidian vault root (update manually if needed)
export OPENPIPES_OBSDIR="\$HOME/ObsidianVault"
EOF
  run "chmod 600 \"$OPENPIPES_CONFIG_FILE\" || true"
  ok "Config written to $OPENPIPES_CONFIG_FILE"
}

final_tweaks() {
  info "Finalizing: ensuring directories & perms"
  ensure_dir "$CACHE_DIR"
  ensure_dir "$OPENPIPES_CONFIG_DIR/.templates"
  # copy templates from repo to config dir if they exist in .openpipes/.templates
  if [ -d "${OPENPIPES_DIR}/.openpipes/.templates" ]; then
    run "cp -r \"${OPENPIPES_DIR}/.openpipes/.templates\" \"$OPENPIPES_CONFIG_DIR/\" || true"
  fi
  ok "Finalization complete"
}

### -------------------------
### MAIN FLOW
### -------------------------
info "=== OPenPipeS Installer starting ==="

install_basic_utils

install_additional_tools

install_go

install_jq

if [ "$SKIP_AMASS" -eq 0 ]; then install_amass; fi
if [ "$SKIP_DNSRECON" -eq 0 ]; then install_dnsrecon; fi
if [ "$SKIP_HTTPX" -eq 0 ]; then install_httpx; fi
if [ "$SKIP_NUCLEI" -eq 0 ]; then install_nuclei; fi
if [ "$SKIP_FEROX" -eq 0 ]; then install_ferox; fi
if [ "$SKIP_KATANA" -eq 0 ]; then install_katana; fi
if [ "$SKIP_GF" -eq 0 ]; then install_gf; fi

install_kits_and_helpers

write_openpipes_config

final_tweaks

ok "=== OPenPipeS Installer finished ==="

cat <<EOF

Next steps / notes:
- Verify that binaries are in your PATH (e.g. which amass httpx nuclei feroxbuster katana)
- Edit .openpipes/config.sh and set OPENPIPES_OBSDIR to your Obsidian Vault path.
- If you installed nuclei, run: nuclei -update-templates (or use the cloned nuclei-templates)
- If you want to pin go-installed versions: edit the script variable (e.g. HTTPX_GO_PKG)
- This installer makes best-effort installs on Debian/Ubuntu/Fedora/macOS.
- For other distros, install the listed packages manually.

If you want, eu já adapto o script para:
- adicionar verificação de checksums para downloads (amass/dnsrecon)
- travar versões específicas para httpx/nuclei/ferox/katana (substituir @latest por tags)
- gerar um playbook Ansible/Dockerfile para ambiente reprodutível

EOF
