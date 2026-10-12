# Security policy

## Reporting a vulnerability

Please do not publish working exploit details in a public issue before there has been a reasonable opportunity to investigate them.

If GitHub private vulnerability reporting is enabled for this repository, use that channel for security-sensitive reports. For ordinary hardening ideas that do not expose users, a normal GitHub issue is fine.

A useful report should include:

- BurnLink version,
- browser and operating system,
- exact reproduction steps,
- expected and observed behavior,
- whether the issue can expose plaintext, bypass one-use retrieval, bypass passcode lockout, or impersonate a viewed receipt.

## Supported version

Security fixes target the latest published BurnLink release.

## Scope and limitations

BurnLink aims to protect pending message contents from casual server-side disclosure and to enforce one successful payload retrieval. It does not claim to prevent a recipient from preserving content they can see or hear.

Browser-side screenshot, copy, focus, and shortcut controls are deterrents only.
