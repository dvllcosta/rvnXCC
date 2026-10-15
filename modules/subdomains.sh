#!/usr/bin/env bash
# =============================================================================
# rvnXC :: subdomains.sh
# Passive + active subdomain enumeration, resolution, and takeover checks.
# =============================================================================

sub_passive() {
	[[ "${SUBPASSIVE:-true}" != "true" ]] && return 0
	info "subfinder: passive enumeration"
	subfinder -d "$DOMAIN" -all -silent -o "${OUT}/subdomains/subfinder.txt" 2>>"$LOG_FILE"

	info "crt.sh: certificate transparency"
	curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
		| jq -r '.[].name_value' 2>/dev/null \
		| sed 's/\*\.//g' | sort -u > "${OUT}/subdomains/crtsh.txt"

	cat "${OUT}/subdomains/subfinder.txt" "${OUT}/subdomains/crtsh.txt" 2>/dev/null \
		| grep -E "\.${DOMAIN}$|^${DOMAIN}$" | sort -u > "${OUT}/subdomains/passive.txt"
	ok "Passive: $(count_lines "${OUT}/subdomains/passive.txt") candidate subdomains"
}

sub_brute() {
	[[ "${SUBBRUTE:-true}" != "true" ]] && return 0
	command -v puredns >/dev/null 2>&1 || { warn "puredns not installed, skipping bruteforce"; return 0; }
	[[ ! -s "$resolvers" ]] && { warn "resolvers file missing/empty (${resolvers}) — skipping bruteforce"; return 0; }
	info "puredns: DNS bruteforce"
	puredns bruteforce "$subs_wordlist" "$DOMAIN" \
		-r "$resolvers" --rate-limit "${PUREDNS_PUBLIC_LIMIT:-0}" \
		-q -w "${OUT}/subdomains/brute.txt" 2>>"$LOG_FILE"
	ok "Bruteforce: $(count_lines "${OUT}/subdomains/brute.txt") subdomains"
}

sub_permute() {
	[[ "${SUBPERMUTE:-true}" != "true" ]] && return 0
	command -v gotator >/dev/null 2>&1 || { warn "gotator not installed, skipping permutations"; return 0; }
	info "gotator: permutations on known subdomains"
	cat "${OUT}/subdomains/passive.txt" "${OUT}/subdomains/brute.txt" 2>/dev/null | sort -u > "${OUT}/subdomains/_seed.txt"
	gotator -sub "${OUT}/subdomains/_seed.txt" -depth 1 -numbers 3 -mindup -adv -md \
		> "${OUT}/subdomains/permutations_raw.txt" 2>>"$LOG_FILE"
	if command -v puredns >/dev/null 2>&1 && [[ -s "$resolvers" ]]; then
		puredns resolve "${OUT}/subdomains/permutations_raw.txt" -r "$resolvers" -q \
			-w "${OUT}/subdomains/permutations.txt" 2>>"$LOG_FILE"
	fi
	ok "Permutations resolved: $(count_lines "${OUT}/subdomains/permutations.txt")"
}

sub_consolidate_resolve() {
	info "dnsx: merging + resolving all candidate subdomains"
	cat "${OUT}"/subdomains/{passive,brute,permutations}.txt 2>/dev/null \
		| grep -E "(^|\.)${DOMAIN//./\\.}$" | sort -u > "${OUT}/subdomains/all.txt"
	dnsx -l "${OUT}/subdomains/all.txt" -silent -resp-only \
		-o "${OUT}/subdomains/resolved.txt" 2>>"$LOG_FILE"
	ok "Resolved: $(count_lines "${OUT}/subdomains/resolved.txt") live DNS records"
}

sub_takeover() {
	[[ "${SUBTAKEOVER:-true}" != "true" ]] && return 0
	command -v nuclei >/dev/null 2>&1 || return 0
	info "nuclei: subdomain takeover templates"
	nuclei -l "${OUT}/subdomains/all.txt" -silent \
		-tags takeover -severity info,low,medium,high,critical \
		-o "${OUT}/subdomains/takeovers.txt" 2>>"$LOG_FILE"
	local hits; hits=$(count_lines "${OUT}/subdomains/takeovers.txt")
	if [[ "$hits" -gt 0 ]]; then
		warn "Possible subdomain takeover: ${hits} hit(s) — see subdomains/takeovers.txt"
		notify "⚠️ ${hits} possible subdomain takeover(s) found"
	fi
}

run_subdomains_module() {
	ensure_dir "${OUT}/subdomains"
	run_phase "subdomains:passive" sub_passive
	run_phase "subdomains:brute" sub_brute
	run_phase "subdomains:permute" sub_permute
	run_phase "subdomains:resolve" sub_consolidate_resolve
	run_phase "subdomains:takeover" sub_takeover
}
