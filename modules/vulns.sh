#!/usr/bin/env bash
# =============================================================================
# rvnXC :: vulns.sh
# Active vulnerability checks. Only runs after confirm_authorization().
# Orchestrates established, public security tools — no custom exploit code.
# =============================================================================

vuln_nuclei() {
	[[ "${NUCLEICHECK:-true}" != "true" ]] && return 0
	command -v nuclei >/dev/null 2>&1 || { warn "nuclei not installed, skipping"; return 0; }
	info "nuclei: CVE + misconfig templates (severity: ${NUCLEI_SEVERITY})"
	nuclei -l "${OUT}/web/webs.txt" -silent \
		-severity "${NUCLEI_SEVERITY:-info,low,medium,high,critical}" \
		-rate-limit "${NUCLEI_RATELIMIT:-150}" ${NUCLEI_EXTRA_ARGS} \
		-o "${OUT}/vulns/nuclei.txt" 2>>"$LOG_FILE"
	local crit; crit=$(grep -ci '\[critical\]' "${OUT}/vulns/nuclei.txt" 2>/dev/null || echo 0)
	[[ "$crit" -gt 0 ]] && notify "🔥 ${crit} CRITICAL nuclei finding(s)"
	ok "nuclei findings: $(count_lines "${OUT}/vulns/nuclei.txt")"
}

vuln_xss() {
	[[ "${XSS:-true}" != "true" ]] && return 0
	command -v dalfox >/dev/null 2>&1 || { warn "dalfox not installed, skipping XSS"; return 0; }
	[[ ! -s "${OUT}/web/gf/xss.txt" ]] && { info "No XSS-pattern candidates, skipping dalfox"; return 0; }
	info "dalfox: XSS scanning on gf-classified candidates"
	dalfox file "${OUT}/web/gf/xss.txt" --silence --no-color \
		-w "${DALFOX_THREADS:-100}" -o "${OUT}/vulns/xss.txt" 2>>"$LOG_FILE" || true
	ok "XSS candidates tested: $(count_lines "${OUT}/web/gf/xss.txt")"
}

vuln_crlf() {
	[[ "${CRLF_CHECKS:-true}" != "true" ]] && return 0
	command -v crlfuzz >/dev/null 2>&1 || return 0
	info "crlfuzz: CRLF injection checks"
	crlfuzz -l "${OUT}/web/webs.txt" -o "${OUT}/vulns/crlf.txt" 2>>"$LOG_FILE" || true
}

vuln_sqli() {
	[[ "${SQLI:-true}" != "true" ]] && return 0
	[[ ! -s "${OUT}/web/gf/sqli.txt" ]] && { info "No SQLi-pattern candidates"; return 0; }
	if [[ "${SQLMAP:-false}" == "true" ]] && command -v sqlmap >/dev/null 2>&1; then
		warn "sqlmap is disabled by default and intentionally not auto-run — invoke it manually, URL by URL:"
		warn "  sqlmap -u \"<url>\" --batch --risk=1 --level=1"
	fi
	info "SQLi-pattern candidates saved for manual review: ${OUT}/web/gf/sqli.txt"
}

vuln_params() {
	[[ "${FUZZPARAMS:-true}" != "true" ]] && return 0
	command -v arjun >/dev/null 2>&1 || { warn "arjun not installed, skipping param discovery"; return 0; }
	info "arjun: hidden parameter discovery"
	ensure_dir "${OUT}/vulns/params"
	local i=0
	while read -r url; do
		[[ -z "$url" ]] && continue
		i=$((i+1)); [[ $i -gt "${PARAM_DISCOVERY_TOP:-15}" ]] && break
		local safe_name; safe_name=$(echo "$url" | sed -E 's#https?://##; s#[/:]#_#g')
		arjun -u "$url" -t "${ARJUN_THREADS:-10}" -oT "${OUT}/vulns/params/${safe_name}.txt" 2>>"$LOG_FILE" || true
	done < "${OUT}/web/webs.txt"
}

run_vulns_module() {
	ensure_dir "${OUT}/vulns"
	confirm_authorization
	run_phase "vulns:nuclei" vuln_nuclei
	run_phase "vulns:xss" vuln_xss
	run_phase "vulns:crlf" vuln_crlf
	run_phase "vulns:sqli" vuln_sqli
	run_phase "vulns:params" vuln_params
}
