#!/usr/bin/env bash
# =============================================================================
# rvnXC :: report.sh
# Aggregates every module's output into assets.jsonl, a risk-scored hotlist,
# and a single-file HTML report. Also implements --diff (new-findings-only).
# =============================================================================

build_asset_store() {
	[[ "${ASSET_STORE:-true}" != "true" ]] && return 0
	info "Building assets.jsonl"
	: > "${OUT}/assets.jsonl"
	while read -r sub; do
		[[ -z "$sub" ]] && continue
		printf '{"type":"subdomain","value":"%s"}\n' "$sub" >> "${OUT}/assets.jsonl"
	done < "${OUT}/subdomains/resolved.txt" 2>/dev/null

	while read -r web; do
		[[ -z "$web" ]] && continue
		printf '{"type":"web","value":"%s"}\n' "$web" >> "${OUT}/assets.jsonl"
	done < "${OUT}/web/webs.txt" 2>/dev/null

	ok "assets.jsonl: $(count_lines "${OUT}/assets.jsonl") entries"
}

build_hotlist() {
	info "Scoring hotlist (riskiest assets first)"
	python3 - "$OUT" "${HOTLIST_TOP:-50}" <<'PYEOF'
import sys, os, json

out, top_n = sys.argv[1], int(sys.argv[2])
scores = {}

def bump(target, points, reason):
    if not target:
        return
    entry = scores.setdefault(target, {"score": 0, "reasons": []})
    entry["score"] += points
    entry["reasons"].append(reason)

def read_lines(path):
    try:
        with open(path, "r", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []

for line in read_lines(os.path.join(out, "subdomains", "takeovers.txt")):
    bump(line.split()[0] if line.split() else line, 40, "possible subdomain takeover")

for line in read_lines(os.path.join(out, "vulns", "nuclei.txt")):
    low = line.lower()
    pts = 5
    if "[critical]" in low: pts = 30
    elif "[high]" in low: pts = 20
    elif "[medium]" in low: pts = 10
    target = line.split()[-1] if line.split() else line
    bump(target, pts, "nuclei: " + line[:80])

for line in read_lines(os.path.join(out, "vulns", "xss.txt")):
    bump(line.split()[0] if line.split() else line, 25, "possible XSS (dalfox)")

for line in read_lines(os.path.join(out, "vulns", "crlf.txt")):
    bump(line, 15, "possible CRLF injection")

for line in read_lines(os.path.join(out, "web", "js_findings.txt")):
    bump(line.split()[-1] if line.split() else line, 15, "exposed token/secret in JS")

ranked = sorted(scores.items(), key=lambda kv: kv[1]["score"], reverse=True)[:top_n]
with open(os.path.join(out, "hotlist.json"), "w") as f:
    json.dump([{"target": t, **d} for t, d in ranked], f, indent=2)

with open(os.path.join(out, "hotlist.txt"), "w") as f:
    for t, d in ranked:
        f.write(f"[{d['score']:>3}] {t}\n")
        for r in d["reasons"][:5]:
            f.write(f"       - {r}\n")

print(f"hotlist: {len(ranked)} ranked assets")
PYEOF
}

build_html_report() {
	info "Rendering report/index.html"
	ensure_dir "${OUT}/report"
	python3 - "$OUT" "$DOMAIN" <<'PYEOF'
import sys, os, json, html, datetime

out, domain = sys.argv[1], sys.argv[2]

def count(path):
    try:
        with open(path, errors="ignore") as f:
            return sum(1 for l in f if l.strip())
    except FileNotFoundError:
        return 0

hotlist = []
hl_path = os.path.join(out, "hotlist.json")
if os.path.exists(hl_path):
    with open(hl_path) as f:
        hotlist = json.load(f)

stats = {
    "Subdomains (resolved)": count(os.path.join(out, "subdomains", "resolved.txt")),
    "Live web hosts": count(os.path.join(out, "web", "webs.txt")),
    "URLs collected": count(os.path.join(out, "web", "urls.txt")),
    "Nuclei findings": count(os.path.join(out, "vulns", "nuclei.txt")),
    "XSS candidates": count(os.path.join(out, "vulns", "xss.txt")),
    "Possible takeovers": count(os.path.join(out, "subdomains", "takeovers.txt")),
}

rows = "".join(f"<tr><td>{html.escape(k)}</td><td>{v}</td></tr>" for k, v in stats.items())
hot_rows = "".join(
    f"<tr><td class='score'>{h['score']}</td><td>{html.escape(h['target'])}</td>"
    f"<td>{html.escape('; '.join(h['reasons'][:3]))}</td></tr>"
    for h in hotlist
)

page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>rvnXC report — {html.escape(domain)}</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1115; color:#e6e6e6; margin:0; padding:2rem; }}
 h1 {{ color:#5ee1c3; }}
 table {{ border-collapse: collapse; width:100%; margin-bottom:2rem; }}
 td, th {{ border:1px solid #2a2d35; padding:.5rem .75rem; text-align:left; }}
 th {{ background:#1a1d24; }}
 .score {{ color:#ff6b6b; font-weight:bold; }}
 .meta {{ color:#9aa0a6; font-size:.9rem; }}
</style></head><body>
<h1>rvnXC — {html.escape(domain)}</h1>
<p class="meta">Generated {datetime.datetime.now().isoformat(timespec='seconds')}</p>
<h2>Summary</h2>
<table><tr><th>Metric</th><th>Count</th></tr>{rows}</table>
<h2>Hotlist (riskiest assets)</h2>
<table><tr><th>Score</th><th>Target</th><th>Why</th></tr>{hot_rows}</table>
</body></html>"""

with open(os.path.join(out, "report", "index.html"), "w") as f:
    f.write(page)
print("report/index.html written")
PYEOF
	ok "Report: ${OUT}/report/index.html"
}

run_diff_mode() {
	[[ "${DIFF:-false}" != "true" ]] && return 0
	local prev="${OUT}/../.last_subdomains_${DOMAIN}.txt"
	if [[ -f "$prev" ]]; then
		info "Diff mode: comparing against previous run"
		comm -13 <(sort "$prev") <(sort "${OUT}/subdomains/resolved.txt") > "${OUT}/subdomains/new.txt"
		ok "New subdomains since last run: $(count_lines "${OUT}/subdomains/new.txt")"
		[[ -s "${OUT}/subdomains/new.txt" ]] && notify "🆕 $(count_lines "${OUT}/subdomains/new.txt") new subdomain(s) found"
	fi
	cp "${OUT}/subdomains/resolved.txt" "$prev" 2>/dev/null
}

run_report_module() {
	ensure_dir "${OUT}/report"
	run_phase "report:diff" run_diff_mode
	run_phase "report:assets" build_asset_store
	run_phase "report:hotlist" build_hotlist
	run_phase "report:html" build_html_report
	notify "Scan finished for ${DOMAIN}. Report: ${OUT}/report/index.html"
}
