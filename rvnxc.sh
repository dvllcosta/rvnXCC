#!/usr/bin/env bash
# =============================================================================
#  _ __ __   ___ __ __   _  __ ____
# | '__|\ \ / / '_ \\ \ / // |/ // ____|
# | |    \ V /| | | |\ V / | ' /| |
# |_|     \_/ |_| |_| \_/  |_|\_\\_____|
#
# rvnXC — a lean recon & vuln-triage pipeline for bug bounty hunters.
# https://github.com/<you>/rvnXC
# License: MIT — see LICENSE. Only test targets you are authorized for.
# =============================================================================
set -uo pipefail

SCRIPTPATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
cd "$SCRIPTPATH" || exit 1

# ---- Load config + modules ---------------------------------------------------
CONFIG_FILE="${SCRIPTPATH}/rvnxc.cfg"
[[ -f "${SCRIPTPATH}/.env" ]] && source "${SCRIPTPATH}/.env"

for mod in core utils osint subdomains web vulns report; do
	# shellcheck source=/dev/null
	source "${SCRIPTPATH}/modules/${mod}.sh"
done

# ---- Defaults (overridable by rvnxc.cfg / flags) ------------------------------
MODE=""
DOMAIN=""
DOMAIN_LIST=""
OUTPUT_BASE="${SCRIPTPATH}/Recon"
RESUME=false
DRY_RUN=false
ASSUME_YES=false
CHECK_TOOLS_STRICT=false
PARALLEL=false

usage() {
	cat <<EOF
rvnXC — recon & vuln-triage pipeline

Target:
  -d <domain>        Single target domain
  -l <file>           File with list of target domains
  -m <name>           Multi-domain label (used with -l) for the report title

Mode (pick one):
  -n                  OSINT only
  -p                  Passive recon only (subdomains + web probe, no active)
  -s                  Subdomains only (enum + resolve + takeover check)
  -r                  Full recon (OSINT + subdomains + web), no active vuln checks
  -a                  All: full recon + active vulnerability checks (asks to confirm authorization)
  -w                  Web/vuln checks only against an existing web list (needs prior -r/-s run)

General:
  -o <dir>            Output base directory (default: ./Recon)
  -f <file>           Custom config file (default: ./rvnxc.cfg)
  -y                  Assume yes to the authorization prompt (CI/automation use only)
  --resume            Skip phases already completed in this target's .state file
  --dry-run           Print the phases that would run, without running them
  --diff              Only highlight assets new since the previous run
  --parallel          Allow modules to use run_parallel() workers where supported
  --check-tools       Exit immediately if required tools are missing
  --health-check      Run environment/tool health check and exit
  -h                  Show this help

Examples:
  ./rvnxc.sh -d example.com -r
  ./rvnxc.sh -d example.com -a
  ./rvnxc.sh -l targets.txt -r -o /data/recon
  ./rvnxc.sh -d example.com -r --resume
EOF
}

# ---- Parse args -----------------------------------------------------------------
while [[ $# -gt 0 ]]; do
	case "$1" in
		-d) DOMAIN="$(sanitize_domain "$2")"; shift 2 ;;
		-l) DOMAIN_LIST="$(sanitize_path "$2")"; shift 2 ;;
		-m) MULTI_LABEL="$2"; shift 2 ;;
		-o) OUTPUT_BASE="$(sanitize_path "$2")"; shift 2 ;;
		-f) CONFIG_FILE="$2"; shift 2 ;;
		-n) MODE="osint"; shift ;;
		-p) MODE="passive"; shift ;;
		-s) MODE="subdomains"; shift ;;
		-r) MODE="recon"; shift ;;
		-a) MODE="all"; shift ;;
		-w) MODE="web"; shift ;;
		-y) ASSUME_YES=true; shift ;;
		--resume) RESUME=true; shift ;;
		--dry-run) DRY_RUN=true; shift ;;
		--diff) DIFF_FLAG=true; shift ;;
		--parallel) PARALLEL=true; shift ;;
		--check-tools) CHECK_TOOLS_STRICT=true; check_tools; exit $? ;;
		--health-check) source "$CONFIG_FILE"; health_check; exit 0 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "Unknown option: $1"; usage; exit 1 ;;
	esac
done

# shellcheck source=/dev/null
[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE" || { echo "Config file not found: $CONFIG_FILE"; exit 1; }
[[ -n "${DIFF_FLAG:-}" ]] && DIFF=true

if [[ -z "$MODE" ]]; then
	usage; exit 1
fi
if [[ -z "$DOMAIN" && -z "$DOMAIN_LIST" ]]; then
	echo "You must pass -d <domain> or -l <file>"; exit 1
fi

run_for_target() {
	local target="$1"
	DOMAIN="$target"
	if ! is_valid_domain "$DOMAIN"; then
		error "Invalid domain after sanitization: '${DOMAIN}' — skipping"
		return 1
	fi
	TARGET="$DOMAIN"
	OUT="${OUTPUT_BASE}/${DOMAIN}"
	ensure_dir "$OUT"
	STATE_FILE="${OUT}/.state"
	LOG_FILE="${OUT}/rvnxc.log"
	JSON_LOG_FILE="${OUT}/rvnxc.jsonl"
	RATE_STATE_FILE="${OUT}/.rate"
	[[ "$RESUME" == "false" ]] && : > "$STATE_FILE"

	banner
	info "Target: ${DOMAIN} | Mode: ${MODE} | Output: ${OUT}"
	notify "Starting mode '${MODE}' on ${DOMAIN}"

	case "$MODE" in
		osint)      run_osint_module ;;
		subdomains) run_subdomains_module ;;
		passive)    run_osint_module; run_subdomains_module; run_web_module; run_report_module ;;
		recon)      run_osint_module; run_subdomains_module; run_web_module; run_report_module ;;
		web)        run_web_module; run_report_module ;;
		all)        run_osint_module; run_subdomains_module; run_web_module; run_vulns_module; run_report_module ;;
	esac

	ok "Done with ${DOMAIN}. Report: ${OUT}/report/index.html"
}

check_tools

if [[ -n "$DOMAIN" ]]; then
	run_for_target "$DOMAIN"
elif [[ -n "$DOMAIN_LIST" ]]; then
	[[ ! -f "$DOMAIN_LIST" ]] && die "List file not found: ${DOMAIN_LIST}"
	while read -r d; do
		[[ -z "$d" ]] && continue
		run_for_target "$(sanitize_domain "$d")"
	done < "$DOMAIN_LIST"
fi
