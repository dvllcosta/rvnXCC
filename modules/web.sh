#!/usr/bin/env bash
# =============================================================================
# rvnXC :: web.sh
# Web probing, screenshots, URL collection, JS analysis, fuzzing.
# =============================================================================

web_probe() {
	[[ "${WEBPROBEFULL:-true}" != "true" ]] && return 0
	info "httpx: probing live web hosts"
	local rate; rate=$(current_rate)
	httpx -l "${OUT}/subdomains/resolved.txt" -silent -follow-redirects \
		-status-code -title -tech-detect -rate-limit "$rate" -timeout "${HTTPX_TIMEOUT:-10}" \
		-threads "${HTTPX_THREADS:-50}" -o "${OUT}/web/httpx.txt" 2>>"$LOG_FILE" \
		|| adapt_rate_down
	awk '{print $1}' "${OUT}/web/httpx.txt" 2>/dev/null > "${OUT}/web/webs.txt"
	ok "Live web hosts: $(count_lines "${OUT}/web/webs.txt")"
}

web_screenshot() {
	[[ "${WEBSCREENSHOT:-true}" != "true" ]] && return 0
	command -v gowitness >/dev/null 2>&1 || { warn "gowitness not installed, skipping screenshots"; return 0; }
	info "gowitness: capturing screenshots"
	ensure_dir "${OUT}/web/screenshots"
	gowitness file -f "${OUT}/web/webs.txt" -P "${OUT}/web/screenshots" --no-http 2>>"$LOG_FILE" || true
}

url_collect() {
	[[ "${URL_CHECK:-true}" != "true" ]] && return 0
	info "Collecting URLs (passive + active)"
	: > "${OUT}/web/urls_raw.txt"
	if command -v gau >/dev/null 2>&1; then
		gau --threads 5 "$DOMAIN" >> "${OUT}/web/urls_raw.txt" 2>>"$LOG_FILE" || true
	fi
	if command -v waybackurls >/dev/null 2>&1; then
		echo "$DOMAIN" | waybackurls >> "${OUT}/web/urls_raw.txt" 2>>"$LOG_FILE" || true
	fi
	if command -v katana >/dev/null 2>&1; then
		katana -list "${OUT}/web/webs.txt" -silent -jc -kf all -d 3 \
			-o "${OUT}/web/urls_katana.txt" 2>>"$LOG_FILE" || true
		cat "${OUT}/web/urls_katana.txt" >> "${OUT}/web/urls_raw.txt" 2>/dev/null
	fi
	sort -u "${OUT}/web/urls_raw.txt" -o "${OUT}/web/urls.txt" 2>/dev/null
	ok "URLs collected: $(count_lines "${OUT}/web/urls.txt")"
}

url_classify() {
	[[ "${URL_GF:-true}" != "true" ]] && return 0
	command -v gf >/dev/null 2>&1 || { warn "gf not installed, skipping pattern classification"; return 0; }
	info "gf: classifying URLs by vuln-pattern"
	ensure_dir "${OUT}/web/gf"
	for pattern in xss sqli ssrf lfi rce redirect idor; do
		gf "$pattern" < "${OUT}/web/urls.txt" > "${OUT}/web/gf/${pattern}.txt" 2>/dev/null
	done
}

js_analysis() {
	[[ "${JSCHECKS:-true}" != "true" ]] && return 0
	info "Extracting + analyzing JS files"
	grep -E '\.js($|\?)' "${OUT}/web/urls.txt" 2>/dev/null | sort -u > "${OUT}/web/js_urls.txt"
	if command -v subjs >/dev/null 2>&1; then
		cat "${OUT}/web/webs.txt" | subjs >> "${OUT}/web/js_urls.txt" 2>/dev/null || true
		sort -u "${OUT}/web/js_urls.txt" -o "${OUT}/web/js_urls.txt"
	fi
	if command -v nuclei >/dev/null 2>&1 && [[ -s "${OUT}/web/js_urls.txt" ]]; then
		nuclei -l "${OUT}/web/js_urls.txt" -silent -tags exposure,token,js \
			-o "${OUT}/web/js_findings.txt" 2>>"$LOG_FILE" || true
	fi
	ok "JS files: $(count_lines "${OUT}/web/js_urls.txt")"
}

web_fuzz() {
	[[ "${FUZZ:-true}" != "true" ]] && return 0
	command -v ffuf >/dev/null 2>&1 || { warn "ffuf not installed, skipping fuzzing"; return 0; }
	[[ ! -s "$fuzz_wordlist" ]] && { warn "fuzz wordlist not found (${fuzz_wordlist})"; return 0; }
	info "ffuf: directory/file fuzzing on top hosts"
	ensure_dir "${OUT}/web/fuzz"
	local top_n="${FUZZ_TOP_HOSTS:-20}"
	local i=0
	while read -r url; do
		[[ -z "$url" ]] && continue
		i=$((i+1)); [[ $i -gt $top_n ]] && break
		local safe_name; safe_name=$(echo "$url" | sed -E 's#https?://##; s#[/:]#_#g')
		ffuf -u "${url}/FUZZ" -w "$fuzz_wordlist" -mc all -fc 404 -sf \
			-noninteractive -of json -o "${OUT}/web/fuzz/${safe_name}.json" \
			-t "${FFUF_THREADS:-40}" -rate "${FFUF_RATELIMIT:-0}" \
			-maxtime "${FFUF_MAXTIME:-300}" 2>>"$LOG_FILE" || true
	done < "${OUT}/web/webs.txt"
}

run_web_module() {
	ensure_dir "${OUT}/web"
	run_phase "web:probe" web_probe
	run_phase "web:screenshot" web_screenshot
	run_phase "web:url_collect" url_collect
	run_phase "web:url_classify" url_classify
	run_phase "web:js_analysis" js_analysis
	run_phase "web:fuzz" web_fuzz
}
