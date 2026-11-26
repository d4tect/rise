# Investigation log

A record of named-pipe candidates flagged by rise and what manual
investigation found. All testing was done on hardware I own.

The point of this log is twofold: show the tool surfaces real issues, and
show the discipline of confirming or killing each lead instead of reporting
weak-DACL pipes as vulnerabilities. A weak or null DACL is a lead, not a bug.
Whether it is exploitable depends on what the owning SYSTEM service does with
the data it receives, which requires reversing the handler.

## Validation summary

Run against a normal workstation, rise independently flagged pipes matching
three published CVEs, plus several still under review:

| Pipe | Owner | Outcome |
|------|-------|---------|
| Everything service pipe | voidtools Everything | Matches CVE-2025-12683 |
| LiveWallpaperPipe | Samsung LiveWallpaperService | Matches CVE-2022-24924 |
| SamsungSystemSupportEngine | Samsung System Support Service | CVE-2026-21024, patched locally |
| warp_service | Cloudflare WARP | Investigated, not a vulnerability |

## warp_service (Cloudflare WARP)

**Flagged:** null DACL, SYSTEM service, pipe feeds a process-creation path.

**Investigation:** Reversed the pipe handler. The function that looked like an
authorisation gate is actually the service building a sandboxed token before
spawning helper processes:

- `LogonUserW` with logon type 5 (service logon) to obtain a token
- `CreateRestrictedToken` with `DISABLE_MAX_PRIVILEGE` to strip privileges
- `CreateWellKnownSid` building a medium integrity-level SID
- `SetTokenInformation` with `TokenIntegrityLevel` to lower the token
- the sandboxed token is what reaches `CreateProcessAsUserW`

**Verdict:** Not a vulnerability. The open pipe into process creation is
deliberate: children run privilege-dropped and low-integrity, so there is no
elevation even if a local user steers the arguments. This is the hardened
state following CVE-2023-1862. Lead killed.

## voidtools Everything

**Flagged:** null DACL on the pipe between the SYSTEM service and the GUI.

**Investigation:** Matches CVE-2025-12683 (reported by Gridware, affecting
Everything <= 1.4.1.1029). Notably, the original finder rated escalation as
only possible when chained with other elements, reinforcing that the null
DACL alone is not a clean escalation.

**Verdict:** Known issue, independently rediscovered by rise.

## Samsung LiveWallpaperPipe

**Flagged:** null DACL, SYSTEM LiveWallpaperService.

**Investigation:** Matches CVE-2022-24924. Public exploit chains the pipe with
a directory junction to make the SYSTEM service act inside System32.

**Verdict:** Known issue. Retained as a study target because the full exploit
chain is documented end to end.

## Samsung SystemSupportEngine

**Flagged:** null DACL.

**Investigation:** Owner is Samsung System Support Service. Local version is
8.0.13.0, past the 8.0.8.0 fix for CVE-2026-21024 (improper privilege
management). The null DACL persists post-fix because the handler logic was
hardened rather than the pipe object locked down.

**Verdict:** Patched locally. Dead end, and a reminder that the DACL is not the
control.

## Still under review

- PACE eden licensing pipes (`WRITE_DAC` for Everyone) — heavily obfuscated
  copy-protection software, no known CVE found
