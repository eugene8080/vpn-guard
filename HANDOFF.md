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

## Current state and next work

The fork and clean local clone were created; upstream remote was added. No audit code has been changed and no downloaded audit has been run on the user's machine. Only this handoff is being added.

Start by checking Git status and reading the latest commits/instructions. Perform a fast-forward-only pull from origin main on the new clean workspace branch; stop on divergence rather than resetting or rewriting. Inspect the existing desktop entry point and export support, then implement the smallest suitable adaptation. Keep findings and validation in the repository so later agents can continue without this chat.
