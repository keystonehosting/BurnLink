# Contributing

Focused bug fixes, compatibility improvements, security hardening, and user-interface improvements are welcome.

## Before opening a pull request

1. Reproduce the behavior on the current `main` branch.
2. Keep changes narrowly scoped.
3. Do not weaken one-use retrieval, encryption, passcode lockout, or receipt validation for convenience.
4. Avoid adding third-party dependencies unless there is a clear maintenance or security benefit.
5. Do not add telemetry, analytics, advertising, or permanent hosted-account requirements.

## Bug reports

Please include:

- operating system,
- browser and version,
- BurnLink version,
- exact steps to reproduce,
- console / terminal errors when relevant,
- whether the problem affects sender, recipient, tunnel setup, media playback, or notifications.

## Development

Run from source:

```bash
python src/burnlink.py --local
```

`--local` is useful for development because it does not require a public tunnel.

## Security issues

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability.
