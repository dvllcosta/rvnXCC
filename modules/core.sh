#!/usr/bin/env bash
# =============================================================================
# rvnXC :: core.sh
# Lifecycle, logging, checkpoint/resume state, and notifications.
# =============================================================================

# ---- Colors -----------------------------------------------------------------
BRED='\033[1;31m'; BGREEN='\033[1;32m'; BYELLOW='\033[1;33m'; BBLUE='\033[1;34m'
BCYAN='\033[1;36m'; RESET='\033[0m'

banner() {
	echo -e "${BCYAN}"
	cat <<'EOF'
            _          __  __  ____
  _ ____ __| |__ __ __ \ \/ / / ___|
 | '__\ \ / / '_ \\ \/ /  \  /  \___ \
 | |   \ V /| | | |>  <   /  \   ___) |
 |_|    \_/ |_| |_/_/\_\ /_/\_\ |____/

        rvnXC - Recon & Vuln Pipeline
EOF
	echo -e "${RESET}"
	echo -e "${BYELLOW}Only scan targets you are explicitly authorized to test (bug bounty scope, written consent).${RESET}"
	echo -e "${BYELLOW}You are responsible for how you use this tool. Misuse may be illegal.${RESET}\n"
}

# ---- Logging -----------------------------------------------------------------
# log LEVEL message
log() {
	local level="$1"; shift
	local msg="$*"
	local ts; ts="$(date '+%Y-%m-%d %H:%M:%S')"
	local color="$RESET"
	case "$level" in
		INFO)  color="$BBLUE" ;;
		OK)    color="$BGREEN" ;;
		WARN)  color="$BYELLOW" ;;
		ERROR) color="$BRED" ;;
	esac
	echo -e "${color}[${ts}] [${level}] ${msg}${RESET}"
	if [[ -n "${LOG_FILE:-}" ]]; then
		echo "[${ts}] [${level}] ${msg}" >> "$LOG_FILE"
	fi
	if [[ "${STRUCTURED_LOGGING:-false}" == "true" && -n "${JSON_LOG_FILE:-}" ]]; then
		printf '{"ts":"%s","level":"%s","msg":%s}\n' "$ts" "$level" "$(printf '%s' "$msg" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read().rstrip()))' 2>/dev/null || printf '"%s"' "$msg")" >> "$JSON_LOG_FILE"
	fi
}

info()  { log INFO  "$@"; }
ok()    { log OK    "$@"; }
warn()  { log WARN  "$@"; }
error() { log ERROR "$@"; }
die()   { error "$@"; exit 1; }

# ---- Checkpoint / resume system ----------------------------------------------
# Every finished phase is appended to $STATE_FILE. On relaunch with -r/--resume
# a phase already present there is skipped, so a killed scan can continue
# instead of restarting from zero.
phase_done() {
	local phase="$1"
	[[ -f "$STATE_FILE" ]] && grep -qxF "$phase" "$STATE_FILE"
}

mark_phase_done() {
	local phase="$1"
	echo "$phase" >> "$STATE_FILE"
}

run_phase() {
	# run_phase <phase_name> <function_to_call>
	local phase="$1"; local fn="$2"
	if [[ "${RESUME:-false}" == "true" ]] && phase_done "$phase"; then
		info "Skipping phase '${phase}' (already completed, --resume)"
		return 0
	fi
	if [[ "${DRY_RUN:-false}" == "true" ]]; then
		info "[dry-run] would run phase: ${phase}"
		return 0
	fi
	info "▶ Starting phase: ${phase}"
	local start_ts; start_ts=$(date +%s)
	if "$fn"; then
		local end_ts; end_ts=$(date +%s)
		ok "✔ Phase '${phase}' finished in $((end_ts - start_ts))s"
		mark_phase_done "$phase"
	else
		warn "✘ Phase '${phase}' reported an error — continuing (check ${LOG_FILE})"
	fi
}

# ---- Notifications ------------------------------------------------------------
notify() {
	local msg="$1"
	[[ "${NOTIFICATION:-false}" != "true" ]] && return 0
	if [[ -n "${DISCORD_WEBHOOK:-}" ]]; then
		curl -s -X POST -H "Content-Type: application/json" \
			-d "{\"content\": \"**rvnXC** [${TARGET:-}]: ${msg}\"}" \
			"$DISCORD_WEBHOOK" >/dev/null 2>&1 &
	fi
	if [[ -n "${SLACK_WEBHOOK:-}" ]]; then
		curl -s -X POST -H "Content-Type: application/json" \
			-d "{\"text\": \"*rvnXC* [${TARGET:-}]: ${msg}\"}" \
			"$SLACK_WEBHOOK" >/dev/null 2>&1 &
	fi
	if [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]]; then
		curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
			--data-urlencode "chat_id=${TELEGRAM_CHAT_ID}" \
			--data-urlencode "text=rvnXC [${TARGET:-}]: ${msg}" >/dev/null 2>&1 &
	fi
}

# ---- Scope guard ---------------------------------------------------------------
# Refuses to run active/vuln phases unless the operator explicitly confirms
# authorization, and (optionally) checks the target against a scope file.
confirm_authorization() {
	if [[ "${ASSUME_YES:-false}" == "true" || "${DRY_RUN:-false}" == "true" ]]; then
		[[ "${DRY_RUN:-false}" == "true" ]] && info "[dry-run] would prompt for authorization confirmation here"
		return 0
	fi
	echo -e "${BYELLOW}You are about to run ACTIVE checks against: ${TARGET:-$DOMAIN_LIST}${RESET}"
	read -r -p "Do you have explicit written authorization to test this target (bug bounty scope / pentest contract)? [y/N] " ans
	case "$ans" in
		[yY][eE][sS]|[yY]) return 0 ;;
		*) die "Authorization not confirmed. Aborting active scan." ;;
	esac
}

check_scope() {
	local host="$1"
	[[ "${INSCOPE:-false}" != "true" ]] && return 0
	[[ ! -f "${SCOPE_FILE:-.scope}" ]] && return 0
	grep -qF "$host" "${SCOPE_FILE:-.scope}"
}

# ---- Cleanup --------------------------------------------------------------------
cleanup() {
	local rc=$?
	if [[ $rc -ne 0 ]]; then
		warn "rvnXC exited with status ${rc}"
	fi
	notify "Scan process ended (exit ${rc})"
}
trap cleanup EXIT
trap 'die "Interrupted by user"' INT TERM
