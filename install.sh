#!/usr/bin/env bash
# =============================================================================
# rvnXC installer — installs the free/open-source toolchain rvnXC orchestrates.
# Tested target: Debian/Ubuntu/Kali. Re-run anytime to update tools.
# =============================================================================
set -uo pipefail

TOOLS_DIR="${HOME}/Tools"
VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

log() { echo -e "\033[1;34m[install]\033[0m $*"; }
ok()  { echo -e "\033[1;32m[install]\033[0m $*"; }
err() { echo -e "\033[1;31m[install]\033[0m $*" >&2; }

mkdir -p "$TOOLS_DIR" "$HOME/go/bin"
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$GOPATH/bin:$PATH"

# ---- System packages ------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
	log "Installing system packages (apt)"
	sudo apt-get update -qq
	sudo apt-get install -y -qq golang-go git curl jq python3 python3-pip whois dnsutils \
		>/dev/null 2>&1 || err "Some apt packages failed — continuing"
elif command -v brew >/dev/null 2>&1; then
	log "Installing system packages (brew)"
	brew install go git curl jq python3 whois bind >/dev/null 2>&1 || err "Some brew packages failed — continuing"
else
	err "Unsupported package manager — install go, git, curl, jq, python3 manually."
fi

GO_VERSION=$(go version 2>/dev/null | awk '{print $3}')
if [[ -z "$GO_VERSION" ]]; then
	err "Go not found on PATH after install — install manually from https://go.dev/dl/ and re-run."
	exit 1
fi
ok "Go: ${GO_VERSION}"

# ---- ProjectDiscovery + core Go tools --------------------------------------------
GO_TOOLS=(
	"github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
	"github.com/projectdiscovery/httpx/cmd/httpx@latest"
	"github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
	"github.com/projectdiscovery/katana/cmd/katana@latest"
	"github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
	"github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
	"github.com/projectdiscovery/subjs@latest"
	"github.com/tomnomnom/waybackurls@latest"
	"github.com/lc/gau/v2/cmd/gau@latest"
	"github.com/tomnomnom/gf@latest"
	"github.com/d3mondev/puredns/v2@latest"
	"github.com/Ice3man543/subzy@latest"
	"github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
	"github.com/sensepost/gowitness@latest"
	"github.com/ffuf/ffuf/v2@latest"
	"github.com/Josue87/gotator@latest"
)

for t in "${GO_TOOLS[@]}"; do
	name=$(basename "${t%@*}")
	log "go install ${name}"
	if $VERBOSE; then
		go install -v "$t"
	else
		go install "$t" >/dev/null 2>&1
	fi
done

# dalfox (XSS)
log "go install dalfox"
go install github.com/hahwul/dalfox/v2@latest >/dev/null 2>&1

# ---- pipx-based tools -------------------------------------------------------------
if command -v pipx >/dev/null 2>&1 || pip3 install --user -q pipx 2>/dev/null; then
	python3 -m pipx ensurepath >/dev/null 2>&1 || true
	log "pipx install arjun, cloud_enum"
	pipx install arjun >/dev/null 2>&1 || true
	pipx install cloud_enum >/dev/null 2>&1 || true
fi

# ---- gf patterns ------------------------------------------------------------------
if command -v gf >/dev/null 2>&1; then
	log "Cloning gf patterns"
	git clone -q https://github.com/1ndianl33t/Gf-Patterns "${TOOLS_DIR}/Gf-Patterns" 2>/dev/null || true
	mkdir -p "$HOME/.gf"
	cp "${TOOLS_DIR}/Gf-Patterns"/*.json "$HOME/.gf/" 2>/dev/null || true
fi

# ---- nuclei templates --------------------------------------------------------------
if command -v nuclei >/dev/null 2>&1; then
	log "Updating nuclei-templates"
	nuclei -ut >/dev/null 2>&1 || true
fi

# ---- resolvers ---------------------------------------------------------------------
log "Fetching trusted resolvers"
curl -s "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
	-o "${TOOLS_DIR}/resolvers.txt" 2>/dev/null || true

# ---- wordlists -----------------------------------------------------------------------
mkdir -p "$(dirname "$0")/data/wordlists"
log "Fetching default wordlists (SecLists subset via OneListForAll)"
curl -s "https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallmicro.txt" \
	-o "$(dirname "$0")/data/wordlists/fuzz_wordlist.txt" 2>/dev/null || true
curl -s "https://raw.githubusercontent.com/trickest/wordlists/main/subdomains.txt" \
	-o "$(dirname "$0")/data/wordlists/subdomains.txt" 2>/dev/null || true

chmod +x "$(dirname "$0")/rvnxc.sh" "$(dirname "$0")/install.sh" 2>/dev/null || true

ok "Install complete. Verify with: ./rvnxc.sh --health-check"
ok "Note: sqlmap is NOT auto-installed by design (rvnXC never runs it for you) —"
ok "  install separately only if you intend to drive it manually: sudo apt install sqlmap"
