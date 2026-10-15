#!/usr/bin/env bash
# =============================================================================
# rvnXC :: osint.sh
# Passive OSINT: whois, emails, GitHub secrets, mail hygiene.
# =============================================================================

osint_whois() {
	[[ "${DOMAIN_INFO:-true}" != "true" ]] && return 0
	command -v whois >/dev/null 2>&1 || return 0
	info "whois lookup"
	whois "$DOMAIN" > "${OUT}/osint/whois.txt" 2>>"$LOG_FILE" || true
}

osint_mail_hygiene() {
	[[ "${MAIL_HYGIENE:-true}" != "true" ]] && return 0
	info "Checking SPF/DMARC records"
	{
		echo "--- SPF ---"
		dig +short TXT "$DOMAIN" | grep -i spf
		echo "--- DMARC ---"
		dig +short TXT "_dmarc.${DOMAIN}"
	} > "${OUT}/osint/mail_hygiene.txt" 2>>"$LOG_FILE"
}

osint_github() {
	[[ "${GITHUB_LEAKS:-true}" != "true" ]] && return 0
	[[ -z "${GITHUB_TOKEN:-}" ]] && { info "GITHUB_TOKEN not set, skipping GitHub secret search"; return 0; }
	if command -v gitleaks >/dev/null 2>&1; then
		info "gitleaks: scanning org/company repos for secrets (requires local clones)"
		info "See docs: clone target org repos into ${OUT}/osint/repos/ then run gitleaks detect"
	fi
}

osint_cloud_enum() {
	[[ "${CLOUD_ENUM:-true}" != "true" ]] && return 0
	command -v cloud_enum >/dev/null 2>&1 || { warn "cloud_enum not installed, skipping"; return 0; }
	info "cloud_enum: scanning for exposed cloud storage"
	cloud_enum -k "$DOMAIN" -l "${OUT}/osint/cloud_enum.txt" 2>>"$LOG_FILE" || true
}

run_osint_module() {
	ensure_dir "${OUT}/osint"
	run_phase "osint:whois" osint_whois
	run_phase "osint:mail_hygiene" osint_mail_hygiene
	run_phase "osint:github" osint_github
	run_phase "osint:cloud_enum" osint_cloud_enum
}
