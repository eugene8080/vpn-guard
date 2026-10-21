# Standalone Windows network checker

Updated: 2026-10-21

Double-click **Network Check.cmd**. It runs once, displays observations, and saves a timestamped UTF-8 text report under `.network-check/reports/`. The menu offers rerun, copy full report, a separate WebRTC browser check, and quit. No administrator access is required. Keep the complete repository together, including its MIT LICENSE.

For a desktop shortcut, run this once from Windows PowerShell in the repository:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-network-check-shortcut.ps1
```

The installer creates `Network Check.lnk` on your desktop and refuses to overwrite an existing shortcut. It changes no network settings. Keep the repository at the same location afterwards. To remove the checker, delete the shortcut and repository folder.

For one noninteractive run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\network-check.ps1
# Optional: omit the active third-party DNS test
powershell -NoProfile -ExecutionPolicy Bypass -File .\network-check.ps1 -NoDnsTest
```

The checker adapts the Windows audit's ipify/ip-api requests, proxy-bypassed curl request, adapter and route queries, configured DNS reads and bash.ws resolver test. It performs no bandwidth test. Network requests have timeouts; a run usually finishes within two minutes, but OS DNS/proxy lookup delays can add time. There is no monitoring, automatic retry loop, agent integration or application launch other than the browser check you select.

PASS means only that the stated observation succeeded. WARNING flags differing observations. FAILURE means a service returned an HTTP denial/error; an unauthenticated API request commonly returns 401, 403 or 405, and this does not show an unhealthy account. UNKNOWN means missing, failed, inconclusive or untested evidence. There is deliberately no overall safe/unsafe verdict.

The report covers Windows proxy configuration presence, proxy environment variable names, up adapters, default routes and the route to one IPv4 destination, observed IPv4 and forced IPv6, provider-reported country/ASN, configured and observed DNS resolvers, and unauthenticated OpenAI/Anthropic HTTP responses. Proxy endpoint values and PAC URLs are omitted because they can contain credentials. No credentials are supplied to probes.

IP equality, ASN membership, DNS geography and interface names cannot establish tunnel coverage or absence of leaks. Failed IPv6 or DNS requests remain unknown. The PowerShell and curl probes do not measure an existing browser or agent process. Timezone and locale are information, not predictions of account suspension. The free ip-api metadata endpoint uses HTTP and is labelled unverified provider evidence.

The WebRTC page runs separately in the browser/profile that opens it. It compares HTTP and STUN observations; differing addresses are a warning, and no STUN candidate is inconclusive. Its result is never incorporated as proof about desktop applications.

Reports include real IPs, DNS addresses, adapter names and locale. They are local, not automatically sent or redacted. Review them before copying or sharing. `.network-check/` is ignored by Git and is the reserved location for any future machine configuration or IP history. No history database or machine configuration is currently created. An explicitly supplied `-ReportDirectory` is your own export destination and may not be Git-ignored.

Legacy `vpn-leak-audit.ps1`, `field-report.ps1`, the Chinese launcher and Unix tools remain available but are not called by this checker. Their historical safety/account claims have not been migrated or endorsed. Use the new entry point for the conservative observations described here. Shared ASN classifiers and their duplicated tables were not modified.

Validation commands (synthetic fixtures, no network):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\lint-ps1.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests\verify-network-check.ps1
node tests/verify-webrtc.cjs
```
