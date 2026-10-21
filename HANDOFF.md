# Standalone Windows network check

Updated: 2026-10-21

## Objective

Adapt this fork into a simple, read-only desktop network check, independent of Orca. The user runs it before opening an agent session or messaging an idle agent. Reuse the existing audit rather than rebuilding its probes.

## Agreed scope

- One-shot desktop shortcut and a timestamped, readable report; rerun and copy/report export where practical.
- No Orca integration, automatic message gating, background monitoring, process killing, or account switching.
- No changes to timezone, language, proxy configuration, DNS configuration or IPv6 bindings.
- Distinguish pass, warning, failure and unknown. A failed or timed-out probe is not proof of safety.
- Report observed public IP/country, proxy settings, tunnel/adapters/routes, IPv4/IPv6 observations, DNS resolver observations, and unauthenticated service connectivity.
- Keep browser WebRTC testing available as a separate browser check. Do not claim a shell probe represents the browser or every running agent.
- Skip the optional bandwidth test by default for the quick check.
- Store any machine-specific configuration, IP history and reports locally and exclude them from Git.

## Findings to verify and correct

Source review found the following in vpn-leak-audit.ps1. Recheck current code before editing:

1. DNS resolver country differing from exit country is labelled a confirmed leak; matching countries are labelled no leak. Geography alone proves neither. Present evidence and uncertainty.
2. A tunnel route to 1.1.1.1 is used to claim all traffic, including UDP/WebRTC, is captured. Limit the conclusion to the tested route and flows.
3. Timezone/language mismatches are not validated predictors of account suspension. Make these informational, not hard safety failures.
4. Proxy-bypassed HTTP requests test a particular request path, not the actual network behaviour of an existing Orca/Claude/Codex process. Label them accurately.
5. A service HTTP response proves reachability, not authenticated access or account health. Distinguish HTTP denial/error from transport failure.
6. ASN/provider heuristics and differing IP observations must not be presented as conclusive proof of residential status or leakage.

Do not run scripts that change settings while investigating. Read existing entry points before executing them.

## Repository and validation

- Origin is the user's fork, eugene8080/vpn-guard; upstream is Mr-Salticidae/vpn-guard.
- MIT licence: preserve upstream copyright and permission notice.
- No upstream AGENTS.md or CLAUDE.md was found during the initial review. Read CONTRIBUTING.md and any instructions now present.
- Preserve Windows PowerShell 5.1 compatibility and UTF-8 BOM for .ps1 files. Keep root scripts in place to preserve relative companion paths.
- Audit remains read-only. Do not publish actual IPs, DNS addresses, credentials or machine paths.
- Existing CI includes PS5.1 parsing, classifier regression and cross-platform checks. Follow CONTRIBUTING.md for changes affecting shared classifiers or duplicated ASN sets.
- Add meaningful tests for changed verdict logic, especially timeouts, incomplete evidence, DNS-country disagreement and limited route coverage. Use synthetic fixtures.
- Review diffs, stage explicit task files, commit with an agent trailer, and push the intended feature branch to origin after validation. Do not push to upstream or merge/deploy automatically.

## Implementation and validation — 2026-10-21, Codex GPT-6

- Started on clean feature branch `eugene8080/standalone-network-check`; `git pull --ff-only origin main` reported already up to date at `ca5eb4e`. Origin and upstream destinations verified; no history rewritten.
- Added `network-check.ps1`, adapting the audit's existing request and local-enumeration mechanisms into a separate conservative Windows entry point. The legacy audit and its shared classifiers remain unchanged; the new checker does not invoke them. See `NETWORK-CHECK.md` for exact probe scope and local report privacy.
- Added `Network Check.cmd`, an optional desktop-shortcut installer, interactive rerun/copy/browser-check commands, and timestamped reports under ignored `.network-check/reports/`. Installed and inspected the local desktop shortcut; no network settings were changed.
- All six reviewed overclaim categories are addressed in the new checker. No overall safety verdict; missing IPv6/DNS/IP/route/HTTP evidence is UNKNOWN. HTTP denial/error is separate from transport failure. DNS-country disagreement and differing IP observations are warnings, not confirmed leaks. ASN/geography metadata, timezone and locale do not establish account safety.
- Updated the separately scoped WebRTC page: no candidates is inconclusive, differing addresses are a warning, matching observations do not establish UDP tunnel coverage. Updated CI's accepted browser result token from LEAK to DIFFERENT.
- Real Windows PowerShell 5.1: repository parser/smart-quote lint passed for 17 scripts; 39 synthetic checker assertions passed, including missing/timeout probes, incomplete DNS metadata, country disagreement, limited route coverage, HTTP denial/error, IP validation, fresh entry-point initialization and new-script BOM checks. Four synthetic browser scenarios passed under Node. These tests are included in Windows CI.
- A live read-only PS5.1 run completed and saved a timestamped UTF-8 BOM report. Failed forced-IPv6 and active-DNS observations remained UNKNOWN; unauthenticated service HTTP errors were distinguished from transport failure. Actual IPs, DNS addresses and proxy values are not recorded in Git. Report/config/history paths verified ignored. The startup smoke found and fixed a PS5.1 parameter-default issue; a fresh-process regression now covers it.
- Not run: Unix/shared-classifier regressions (their code/tables are unchanged; local work uses PowerShell), browser live STUN validation, authenticated service checks or a visual desktop interaction test. Browser verdict logic was exercised with synthetic HTTP/ICE fixtures. Existing upstream CI retains cross-platform checks.
- Out of scope and untouched: Orca integration, monitoring, process/account control, settings-changing scripts, upstream pushes, and pc-settings. Legacy tools retain their historical claims and are explicitly distinguished in the new documentation; use the standalone entry point for this task's verdicts.
