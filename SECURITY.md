# Security Policy

## Secrets

- All API keys, webhooks and tokens belong in `.env` (copy from `.env.example`). `.env` is gitignored and must never be committed.
- `rvnxc.cfg` holds toggles/thresholds only — no secrets.
- If a secret is ever committed by mistake: rotate it immediately, then rewrite history (`git filter-repo` or BFG) before force-pushing.

## Scope / authorization

- `-a` (active vulnerability checks) will not run without an explicit "yes" at the authorization prompt, or `-y` for scripted/CI use.
- Set `INSCOPE=true` and populate `.scope` to hard-restrict which hosts rvnXC is allowed to touch.
- rvnXC calls third-party tools (nuclei, dalfox, ffuf, sqlmap if you invoke it manually, …) — it does not ship custom exploit code.

## Reporting a vulnerability in rvnXC itself

Open a private security advisory on this repository (or email the maintainer listed in the repo profile) rather than a public issue, so any real bug in the tooling isn't disclosed before a fix ships.
