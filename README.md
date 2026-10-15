# rvnXC

A lean, modular recon & vuln-triage pipeline for bug bounty hunters and pentesters — built on free, open-source tooling (ProjectDiscovery's `subfinder` / `httpx` / `nuclei` / `katana`, plus `dalfox`, `ffuf`, `gf`, `puredns`, and friends).

> **Legal:** rvnXC is for authorized security testing only — bug bounty scopes, written pentest authorization, or assets you own. Scanning targets without consent may be illegal. You are responsible for how you use this tool.

## Why rvnXC and not just reconFTW?

rvnXC follows the same recon-pipeline shape popularized by tools like reconFTW, but is deliberately smaller, and adds a few things that pipeline didn't have out of the box:

| | |
|---|---|
| **Checkpoint/resume** | Every phase is logged to a per-target `.state` file. Kill the scan, re-run with `--resume`, and only the unfinished phases run. |
| **Risk-scored hotlist** | `report/index.html` + `hotlist.json` rank every finding (takeover > critical CVE > XSS > …) instead of dumping flat text files you have to read yourself. |
| **Scope guard** | Active checks (`-a`) refuse to run until you explicitly confirm authorization at the prompt (or pass `-y` for CI). Optional `.scope` allow-list via `INSCOPE=true`. |
| **sqlmap is never auto-run** | SQLi candidates are classified and saved for manual review; rvnXC prints the exact `sqlmap` command instead of firing it blindly at every URL. |
| **Adaptive rate limiting** | Optional backoff/speed-up on `httpx` based on error bursts, without needing a cloud fleet. |
| **Secrets stay out of config** | API keys and webhooks live in a gitignored `.env`, never in the tracked `.cfg`. |
| **Diff mode** | `--diff` highlights only what's new since your last run against the same target. |
| **Dry-run** | `--dry-run` prints the phase plan without touching the network. |

## Architecture

```
rvnXC/
├── rvnxc.sh              # entry point: arg parsing, mode dispatch, checkpointing
├── rvnxc.cfg              # toggles, thresholds, thread/rate counts
├── .env.example            # copy to .env for API keys & webhooks (gitignored)
├── install.sh               # installs the toolchain (Go tools, pipx tools, wordlists)
├── modules/
│   ├── core.sh              # logging, banner, checkpoint system, notifications, scope guard
│   ├── utils.sh              # sanitization, dependency checks, parallel runner, rate limiter
│   ├── osint.sh               # whois, SPF/DMARC, cloud_enum, GitHub leak hooks
│   ├── subdomains.sh           # subfinder + crt.sh, puredns brute/permute, dnsx resolve, takeover check
│   ├── web.sh                   # httpx probing, gowitness screenshots, URL collection, gf, JS analysis, ffuf
│   ├── vulns.sh                  # nuclei, dalfox, crlfuzz, arjun — gated behind confirm_authorization()
│   └── report.sh                  # assets.jsonl, risk-scored hotlist, single-file HTML report, diff mode
├── data/wordlists/                 # fuzz/subdomain wordlists (fetched by install.sh)
├── Docker/Dockerfile
└── .github/workflows/ci.yml          # shellcheck on every push
```

Each module exposes `run_<name>_module`, called from `rvnxc.sh` depending on mode. Every function inside a module runs through `run_phase "name" fn`, which handles logging, timing, checkpointing and dry-run — so adding a new check is just: write a function, call it through `run_phase`.

## Installation

```bash
git clone https://github.com/<you>/rvnXC
cd rvnXC
./install.sh --verbose
cp .env.example .env          # fill in tokens/webhooks you actually use
```

Verify everything is in place:

```bash
./rvnxc.sh --health-check
```

## Usage

```bash
# Full recon, no active checks
./rvnxc.sh -d example.com -r

# Full recon + active vuln checks (will ask you to confirm authorization)
./rvnxc.sh -d example.com -a

# Passive-only footprint
./rvnxc.sh -d example.com -p

# Multiple targets from a file
./rvnxc.sh -l targets.txt -r -o /data/recon

# Resume a scan that got killed halfway through
./rvnxc.sh -d example.com -r --resume

# See what would run without touching the network
./rvnxc.sh -d example.com -a --dry-run

# Only show what's new since the last run on this target
./rvnxc.sh -d example.com -r --diff
```

### Flags

| Flag | Meaning |
|---|---|
| `-d <domain>` | Single target |
| `-l <file>` | List of targets, one per line |
| `-n` | OSINT only |
| `-p` | Passive recon only |
| `-s` | Subdomains only |
| `-r` | Full recon (OSINT + subdomains + web), no active checks |
| `-a` | Full recon + active vuln checks |
| `-w` | Web/vuln checks only (reuse an existing subdomain list) |
| `-o <dir>` | Output base directory (default `./Recon`) |
| `-f <file>` | Custom config file |
| `-y` | Skip the authorization prompt (CI use only — know what you're doing) |
| `--resume` | Skip phases already completed |
| `--dry-run` | Print the phase plan, don't execute |
| `--diff` | Only report assets new since the previous run |
| `--check-tools` | Exit non-zero if required tools are missing |
| `--health-check` | Validate environment and exit |

## Configuration

Everything togglable lives in `rvnxc.cfg` — module on/off switches, thread counts, rate limits, severity filters. Copy it per engagement and pass with `-f mytarget.cfg` if you want different settings without editing the tracked default.

Secrets (`GITHUB_TOKEN`, `SHODAN_API_KEY`, `DISCORD_WEBHOOK`, …) go in `.env`, which `rvnxc.sh` sources automatically and which is gitignored — so they never end up in a commit.

## Output layout

```
Recon/<domain>/
├── osint/
├── subdomains/
│   ├── all.txt, resolved.txt, takeovers.txt, new.txt (diff mode)
├── web/
│   ├── webs.txt, urls.txt, js_urls.txt, gf/*.txt, screenshots/
├── vulns/
│   ├── nuclei.txt, xss.txt, crlf.txt, params/
├── assets.jsonl            # every discovered asset, one JSON object per line
├── hotlist.json / .txt     # risk-ranked findings
├── report/index.html       # single-file visual report
├── rvnxc.log / .jsonl
└── .state                  # checkpoint file consumed by --resume
```

## Notifications

Set `NOTIFICATION=true` in `rvnxc.cfg` and fill `DISCORD_WEBHOOK`, `SLACK_WEBHOOK`, or `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` in `.env` to get a ping on scan start/finish and on high-signal findings (subdomain takeover, critical nuclei hit, new diff assets).

## Docker

```bash
docker build -t rvnxc -f Docker/Dockerfile .
docker run -it --rm -v "${PWD}/Recon:/rvnXC/Recon" rvnxc -d example.com -r
```

## Contributing

Issues and PRs welcome. Run `shellcheck modules/*.sh rvnxc.sh install.sh` before submitting — CI runs the same check.

## Disclaimer

rvnXC orchestrates third-party, publicly available security tools (subfinder, httpx, nuclei, dalfox, ffuf, etc.) — it does not contain custom exploit code. It is provided for authorized security research only. The authors assume no liability for misuse.

## License

MIT — see [LICENSE](LICENSE).
