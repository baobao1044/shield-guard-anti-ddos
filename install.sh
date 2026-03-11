#!/usr/bin/env bash
# ============================================================================
# Shield Guard - Installer
# Usage: curl -sSL https://raw.githubusercontent.com/user/shield-guard/main/install.sh | bash
# ============================================================================

set -e

REPO="https://github.com/user/shield-guard"
RELEASE_URL="https://github.com/user/shield-guard/releases/latest/download/shield.js"
INSTALL_DIR="${SHIELD_DIR:-/opt/shield-guard}"
CONFIG_FILE="$INSTALL_DIR/shield.config.json"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

info()    { echo -e "${CYAN}[Shield]${NC} $*"; }
success() { echo -e "${GREEN}[Shield]${NC} $*"; }
warn()    { echo -e "${YELLOW}[Shield]${NC} $*"; }
error()   { echo -e "${RED}[Shield]${NC} $*" >&2; exit 1; }

echo -e "\n${BOLD}${CYAN}"
echo "  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ "
echo "  ╚════██║██╔══██║██║██╔══╝  ██║     ██╔══██╗"
echo "  ███████║██║  ██║██║███████╗███████╗██████╔╝"
echo -e "  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ${NC}"
echo -e "  ${BOLD}Shield Guard Installer${NC}\n"

# ── Check OS ──
OS=$(uname -s)
if [[ "$OS" != "Linux" && "$OS" != "Darwin" ]]; then
  error "Unsupported OS: $OS (Linux/macOS only)"
fi

# ── Check Node.js ──
if ! command -v node &>/dev/null; then
  warn "Node.js not found. Installing via nvm..."
  curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
  export NVM_DIR="$HOME/.nvm"
  # shellcheck disable=SC1091
  [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
  nvm install --lts
fi

NODE_VER=$(node -e "process.stdout.write(process.version.slice(1).split('.')[0])")
if [[ "$NODE_VER" -lt 18 ]]; then
  error "Node.js >= 18 required (found v$NODE_VER)"
fi
success "Node.js v$(node -v | tr -d 'v') OK"

# ── Create install dir ──
info "Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# ── Download shield.js ──
info "Downloading shield.js..."
if command -v curl &>/dev/null; then
  curl -sSL "$RELEASE_URL" -o "$INSTALL_DIR/shield.js"
elif command -v wget &>/dev/null; then
  wget -q "$RELEASE_URL" -O "$INSTALL_DIR/shield.js"
else
  error "curl or wget required"
fi
success "Downloaded shield.js"

# ── Create config if not exists ──
if [[ ! -f "$CONFIG_FILE" ]]; then
  info "Creating default config at $CONFIG_FILE"

  # Prompt for target
  echo ""
  read -rp "  Enter your backend server URL [http://localhost:3000]: " TARGET
  TARGET="${TARGET:-http://localhost:3000}"

  read -rp "  Enter HTTP port [80]: " HTTP_PORT
  HTTP_PORT="${HTTP_PORT:-80}"

  read -rp "  Enable HTTPS? (y/n) [n]: " ENABLE_HTTPS
  ENABLE_HTTPS="${ENABLE_HTTPS:-n}"

  read -rp "  Dashboard password (leave empty for no auth): " DASHBOARD_PASS

  HTTPS_BLOCK=""
  if [[ "$ENABLE_HTTPS" == "y" || "$ENABLE_HTTPS" == "Y" ]]; then
    read -rp "  HTTPS port [443]: " HTTPS_PORT
    HTTPS_PORT="${HTTPS_PORT:-443}"
    HTTPS_BLOCK='"httpsPort": '"$HTTPS_PORT"', "tls": { "selfSigned": true },'
  fi

  PASS_LINE=""
  [[ -n "$DASHBOARD_PASS" ]] && PASS_LINE='"dashboardPassword": "'"$DASHBOARD_PASS"'",'

  cat > "$CONFIG_FILE" <<EOF
{
  "target": "$TARGET",
  "port": $HTTP_PORT,
  $HTTPS_BLOCK
  $PASS_LINE
  "shield": {
    "l3": { "enabled": true },
    "l4": { "enabled": true },
    "l7": { "enabled": true }
  }
}
EOF
  success "Config created: $CONFIG_FILE"
else
  warn "Config already exists at $CONFIG_FILE (skipping)"
fi

# ── Create launcher script ──
cat > "$INSTALL_DIR/start.sh" <<'LAUNCHER'
#!/usr/bin/env bash
cd "$(dirname "$0")"
exec node shield.js --config shield.config.json "$@"
LAUNCHER
chmod +x "$INSTALL_DIR/start.sh"

# ── Symlink to /usr/local/bin ──
if [[ -w /usr/local/bin ]]; then
  ln -sf "$INSTALL_DIR/start.sh" /usr/local/bin/shield-guard
  success "Installed CLI: shield-guard"
fi

# ── Optional systemd service ──
if command -v systemctl &>/dev/null && [[ -d /etc/systemd/system ]]; then
  echo ""
  read -rp "  Setup systemd service for auto-start? (y/n) [y]: " SETUP_SYSTEMD
  SETUP_SYSTEMD="${SETUP_SYSTEMD:-y}"

  if [[ "$SETUP_SYSTEMD" == "y" || "$SETUP_SYSTEMD" == "Y" ]]; then
    cat > /etc/systemd/system/shield-guard.service <<UNIT
[Unit]
Description=Shield Guard Anti-DDoS Proxy
After=network.target

[Service]
Type=simple
User=nobody
WorkingDirectory=$INSTALL_DIR
ExecStart=$(which node) $INSTALL_DIR/shield.js --config $CONFIG_FILE
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable shield-guard
    systemctl start shield-guard
    success "systemd service enabled and started"
    info "Manage with: systemctl [start|stop|restart|status] shield-guard"
    info "Logs: journalctl -u shield-guard -f"
  fi
fi

# ── Done ──
CONFIG_DATA=$(node -e "try{const c=require('$CONFIG_FILE');console.log(c.port||8080)}catch(e){console.log(8080)}" 2>/dev/null || echo "8080")
echo ""
echo -e "${GREEN}${BOLD}✓ Shield Guard installed successfully!${NC}"
echo ""
echo -e "  ${CYAN}Start:${NC}     cd $INSTALL_DIR && node shield.js"
echo -e "  ${CYAN}Dashboard:${NC} http://localhost:$CONFIG_DATA/shield-dashboard"
echo -e "  ${CYAN}Health:${NC}    http://localhost:$CONFIG_DATA/shield-health"
echo -e "  ${CYAN}Config:${NC}    $CONFIG_FILE"
echo ""
