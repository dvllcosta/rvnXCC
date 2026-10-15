#!/usr/bin/env bash
# =============================================================================
# rvnXC :: utils.sh
# Shared helpers: sanitization, dependency checks, parallel runner, rate limit.
# =============================================================================

# ---- Input sanitization -------------------------------------------------------
# Strips anything that is not alnum/dot/dash/underscore/slash/colon to block
# command injection via target names coming from -d/-l/-m.
sanitize_domain() {
	local raw="$1"
	printf '%s' "$raw" | tr -d '\n\r' | sed -E 's/[^a-zA-Z0-9._-]//g'
}

sanitize_path() {
	local raw="$1"
	printf '%s' "$raw" | tr -d '\n\r' | sed -E 's/[^a-zA-Z0-9._/:-]//g'
}

is_valid_domain() {
	local d="$1"
	[[ "$d" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]
}

# ---- Dependency checks ---------------------------------------------------------
REQUIRED_TOOLS=(subfinder httpx nuclei katana dnsx dalfox ffuf curl jq)
OPTIONAL_TOOLS=(naabu gau waybackurls gf crlfuzz gowitness sqlmap notify python3)

check_tools() {
	local missing=()
	for t in "${REQUIRED_TOOLS[@]}"; do
		command -v "$t" >/dev/null 2>&1 || missing+=("$t")
	done
	if [[ ${#missing[@]} -gt 0 ]]; then
		error "Missing required tools: ${missing[*]}"
		error "Run: ./install.sh"
		if [[ "${CHECK_TOOLS_STRICT:-false}" == "true" ]]; then
			exit 1
		fi
		return 1
	fi
	local missing_opt=()
	for t in "${OPTIONAL_TOOLS[@]}"; do
		command -v "$t" >/dev/null 2>&1 || missing_opt+=("$t")
	done
	if [[ ${#missing_opt[@]} -gt 0 ]]; then
		warn "Optional tools not found (some modules will be skipped): ${missing_opt[*]}"
	fi
	return 0
}

health_check() {
	banner
	info "Running health check..."
	check_tools
	[[ -d "$NUCLEI_TEMPLATES_PATH" ]] && ok "nuclei-templates found at ${NUCLEI_TEMPLATES_PATH}" \
		|| warn "nuclei-templates not found at ${NUCLEI_TEMPLATES_PATH} (run: nuclei -ut)"
	local free_gb
	free_gb=$(df -Pk "$PWD" | awk 'NR==2{print int($4/1024/1024)}')
	if [[ "$free_gb" -lt "${MIN_DISK_SPACE_GB:-2}" ]]; then
		warn "Low disk space: ${free_gb}GB free"
	else
		ok "Disk space OK: ${free_gb}GB free"
	fi
	ok "Health check complete."
}

# ---- Parallel runner -------------------------------------------------------------
# run_parallel <max_jobs> <command...read from stdin, one arg per line>
# A lightweight replacement for GNU parallel / Ax fleets: farms a line-delimited
# input list out to N worker processes via xargs, no extra dependency beyond
# coreutils. Falls back to sequential if xargs -P is unavailable.
run_parallel() {
	local max_jobs="$1"; shift
	local cmd=("$@")
	if xargs --version >/dev/null 2>&1; then
		xargs -P "$max_jobs" -I{} -- "${cmd[@]}" {}
	else
		while read -r line; do
			"${cmd[@]}" "$line"
		done
	fi
}

# ---- Adaptive rate limiting -------------------------------------------------------
# Tracks a mutable rate in $RATE_STATE_FILE; call adapt_rate_down on a 429/503
# burst and adapt_rate_up on a clean pass. Consumers read current_rate().
current_rate() {
	if [[ -f "${RATE_STATE_FILE:-}" ]]; then
		cat "$RATE_STATE_FILE"
	else
		echo "${HTTPX_RATELIMIT:-150}"
	fi
}

adapt_rate_down() {
	[[ "${ADAPTIVE_RATE_LIMIT:-false}" != "true" ]] && return 0
	local rate; rate=$(current_rate)
	local new_rate; new_rate=$(python3 -c "print(max(${MIN_RATE_LIMIT:-10}, int(${rate} * ${RATE_LIMIT_BACKOFF_FACTOR:-0.5})))" 2>/dev/null || echo "$rate")
	echo "$new_rate" > "$RATE_STATE_FILE"
	warn "Adaptive rate limit: backing off to ${new_rate} req/s"
}

adapt_rate_up() {
	[[ "${ADAPTIVE_RATE_LIMIT:-false}" != "true" ]] && return 0
	local rate; rate=$(current_rate)
	local new_rate; new_rate=$(python3 -c "print(min(${MAX_RATE_LIMIT:-500}, int(${rate} * ${RATE_LIMIT_INCREASE_FACTOR:-1.2}) + 1))" 2>/dev/null || echo "$rate")
	echo "$new_rate" > "$RATE_STATE_FILE"
}

# ---- Misc helpers -------------------------------------------------------------------
count_lines() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

ensure_dir() { mkdir -p "$1"; }

timestamp() { date '+%Y%m%d_%H%M%S'; }
