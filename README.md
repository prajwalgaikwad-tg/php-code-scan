# PHP Security Scan

A **universal, read-only** security scanner for PHP applications. Clone it to a
server, run one command, and get a plain-English HTML report plus a
machine-readable JSON report.

It auto-detects the application type (WordPress / Composer framework / plain
PHP), runs trusted free scanners, and **never modifies application code or
touches the database.**

---

## What it checks

| Area | Tool | Confidence |
|---|---|---|
| Dependency CVEs | **composer audit** | Confirmed (published CVEs) |
| Source-code vulnerabilities | **Semgrep CE** (php, security-audit, owasp-top-ten, secrets, xss rulesets) | Analyzed (data-flow) |
| Leaked secrets / credentials | **gitleaks** | Confirmed |
| PHP runtime vs php2shell (CVE-2026-109618/109619) | built-in version check | Confirmed |
| PHP runtime hardening (`display_errors`, `allow_url_include`, …) | built-in `php.ini` check | — |
| WordPress core/plugin/theme CVEs | **wp-cli + Wordfence feed** (WP only) | Confirmed |
| Fallback code patterns | built-in regex | Review (appendix only) |

All tools are free and safe for commercial use.

---

## Quick start (git clone — recommended)

On the target server:

```bash
git clone <your-repo-url> php-security-scan
cd php-security-scan
chmod +x scan.sh
./scan.sh /var/www/your-app
```

That's it. On first run it fetches what it needs (Semgrep via `uv`, gitleaks)
into its own `bin/` folder — nothing is installed system-wide.

Open the report:

```
reports/<hostname>_<timestamp>/report.html   <- open in a browser
reports/<hostname>_<timestamp>/report.json   <- for tooling / records
```

Reports are named `<hostname>_<timestamp>`, so scanning multiple servers (or the
same server multiple times) never overwrites previous reports.

---

## Options

| Command | Effect |
|---|---|
| `./scan.sh /path/to/app` | Scan a specific directory |
| `./scan.sh` | Scan the current directory |
| `./scan.sh --dangerous /path` | Report only Critical + High (dev-focused) |
| `./scan.sh --min-severity medium /path` | Report Medium and above |
| `./scan.sh --s3 s3://bucket/prefix /path` | Also upload the report to S3 (see below) |
| `./scan.sh --no-fetch /path` | Never download; use only tools already present/bundled |
| `./scan.sh --cleanup` | Remove downloaded tools (`bin/`) and cache, **keep reports** |
| `./scan.sh --help` | Show usage |

---

## Uploading reports to S3 (optional)

On EC2, the cleanest way to collect reports centrally is S3 via the instance's
**IAM role** — no credentials to manage:

```bash
./scan.sh --s3 s3://my-security-reports/php-scans /var/www/your-app
```

The report is uploaded to `s3://my-security-reports/php-scans/<hostname>_<timestamp>/`.

Requirements:
- The **AWS CLI** installed on the instance (`aws --version`).
- The instance's **IAM role** must allow `s3:PutObject` on that bucket/prefix, e.g.:

```json
{
  "Effect": "Allow",
  "Action": ["s3:PutObject"],
  "Resource": "arn:aws:s3:::my-security-reports/php-scans/*"
}
```

Without `--s3`, reports simply stay on disk in `reports/`.

---

## Requirements

- **bash** + standard Unix tools (present on any Linux/macOS server).
- **PHP CLI** — builds the report and runs wp-cli/config checks (almost always present on a PHP server).
- **composer** — for the dependency scan (usually already installed).
- **curl** + **python3** — only needed the first time, to fetch Semgrep/gitleaks. Optional if pre-bundled.

No Docker. No root. No system package installs. Everything lives in this folder.

---

## How tools are handled (self-contained)

- First run (with internet) fetches Semgrep (via `uv`) and gitleaks into `bin/`.
  Nothing is installed system-wide.
- Re-runs reuse them — fast, and work offline.
- `--cleanup` wipes `bin/` and `cache/` but keeps `reports/`.
- Auto-detects OS + CPU architecture, so it works on **x86_64** and **arm64 / AWS Graviton**.

### Air-gapped servers

If the server has no outbound internet, prepare the folder on a machine that
does (run it once so `bin/` and `cache/` fill up), copy the whole folder over,
and run with `--no-fetch`.

---

## Reading the report

- **Executive summary** — plain-English overview at the top.
- **php2shell runtime status** — confirms whether PHP is patched against the Oct 2026 RCE incident.
- **Priority action list** — dependency updates to do first (one `composer update` each).
- **Key code issues** — real code problems found by data-flow analysis.
- **Confidence tiers**: `Confirmed` (CVE) / `Analyzed` (Semgrep) / `Review` (pattern).
- Repeated issues are **grouped into distinct problems** with occurrence counts.
- Low-confidence regex matches live in a collapsed **appendix**.

---

## Important: what a clean report does and does not mean

This tool finds **known** vulnerabilities and **known** insecure patterns. A
clean report does **not** prove the application is secure, detect active
break-ins, or replace a manual security review. For a critical system, pair this
automated scan with a **manual penetration test** of the high-risk areas.

---

## Safety summary

- Read-only on the target app; output only inside this folder (or S3 if `--s3`).
- No database access. No system changes — no Docker, no root, no system packages.
- `--cleanup` leaves nothing behind except the reports.
- Run in **UAT/staging first**, validate, then production.
