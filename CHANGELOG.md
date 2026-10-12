# Changelog

## 3.0 — 2026-10-12

- Rebuilt sender and recipient interfaces with a restrained Windows-style design.
- Added automatic light / dark theme support and improved mobile layout.
- Added Spotify tracks and encrypted audio attachments with optional start times.
- Audio remains playable after the private message timer ends.
- Added Waiting / Opened / Viewed receipt states.
- Added best-effort Windows viewed notifications and notification sound.
- Changed passcodes into a second encryption factor; raw passcodes are not sent to the BurnLink Python server.
- Added strong passcode generation and show / hide controls.
- Retained five-attempt lockout, pre-open revoke, one-use atomic retrieval, expiry, watermark, focus hiding, shortcut guards, and hold-to-reveal mode.
- Improved Windows idle-sleep prevention while BurnLink is active.
- Added verified reuse of a previously downloaded `cloudflared` helper when release metadata is temporarily unavailable.
- Removed development artifacts and rewrote distribution documentation.
