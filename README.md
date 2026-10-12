# BurnLink

**One-time browser messages from your Windows PC. The recipient installs nothing.**

BurnLink creates temporary links for text, images, audio, and Spotify tracks. The sender runs BurnLink locally; the recipient opens the link in a modern browser. Pending message content is encrypted before storage and removed after the one successful retrieval.

> BurnLink can discourage screenshots and copying, but no website can guarantee that visible or audible content cannot be captured.

## Download

**Windows portable build:** [Download BurnLink 3.0](https://github.com/keystonehosting/BurnLink/releases/download/v3.0/BurnLink-Windows-v3.0.zip)

The release also includes `SHA256SUMS.txt` so the download can be verified.

No Python installation is required for the portable build.

## Quick start

1. Download and extract `BurnLink-Windows-v3.0.zip`.
2. Open the extracted `BurnLink-Windows` folder.
3. Double-click `Start-BurnLink.cmd`.
4. Click **Start connection** and wait for **Ready**.
5. Create the message and send the complete generated link.
6. Keep BurnLink and the PC running until the link is opened, revoked, or expires.

The recipient only needs a modern browser.

## Features

- One successful retrieval per link
- Text up to 20,000 characters
- One image: PNG, JPEG, WebP, or GIF
- Attached MP3, M4A/AAC, OGG, WAV, or WebM audio
- Spotify track embeds
- Optional audio / Spotify start timestamp
- Audio can continue after the private text or image disappears
- Adjustable reading timer
- Expiration for unopened links
- Optional passcode
- Five-attempt passcode lockout
- Sender-side revoke before retrieval
- Waiting / Opened / Viewed states
- Best-effort Windows viewed notification and sound
- Random per-view watermark
- Focus-loss hiding
- Shortcut / copy / print deterrents
- Optional hold-to-reveal mode
- Automatic light / dark theme
- No recipient account, extension, or installation
- No permanent BurnLink server account required

## How one-use delivery works

Ordinary `GET` and `HEAD` requests do not consume a message, so most link-preview crawlers cannot burn it simply by fetching the page.

When the recipient explicitly opens the message, the server atomically removes the encrypted payload before returning it. Concurrent open attempts therefore produce at most one successful retrieval.

A successful retrieval cannot be repeated. Reloading or reopening the link after retrieval will not fetch the payload again.

## Encryption and passcodes

Message text, image data, attached audio, Spotify URL, start time, and recipient privacy settings are encrypted in the sender's browser with AES-256-GCM before BurnLink stores them.

The random message key is carried in the URL fragment (`#...`). URL fragments are not sent in normal HTTP requests.

When a passcode is enabled, BurnLink derives key material in the browser with PBKDF2-SHA-256 and uses it to wrap the random message key. The raw passcode is not sent to the Python server. The server receives only a derived verifier used for lockout enforcement.

For a more detailed description, see [Security model](docs/SECURITY-MODEL.md).

## Viewed receipts

BurnLink distinguishes retrieval from confirmed display:

- **Waiting** — payload has not been retrieved.
- **Opened — display not confirmed** — ciphertext was retrieved, but successful rendering has not been acknowledged.
- **Viewed** — the recipient page successfully decrypted and rendered the message, then sent a one-time display receipt.

Viewed notifications are best effort. A modified client can suppress a receipt, and network failure can prevent it from reaching the sender.

## Music behavior

BurnLink supports either a Spotify track or one attached audio file per message.

Optional start points accept:

```text
83
1:23
1:02:03
```

The private message timer only clears the message / image area. Audio controls remain available in the already-open tab so the recipient can finish listening.

## Public connection

BurnLink uses Cloudflare's official `cloudflared` Quick Tunnel to expose the local recipient page to the Internet. The helper is downloaded on demand from Cloudflare's official GitHub release and verified against the published SHA-256 digest before use.

Quick Tunnels have no uptime guarantee. The sender's PC, Internet connection, BurnLink process, and tunnel must remain available until an unopened link is used or expires.

## Screenshot and capture limits

BurnLink includes browser-side privacy deterrents such as:

- hiding on detected screenshot / developer / modifier-key actions,
- hiding when the tab loses focus,
- copy / selection / print deterrents,
- a random watermark,
- optional hold-to-reveal mode.

These are deterrents, not capture prevention. Operating-system tools, browser extensions, modified browsers, screen recorders, capture hardware, or a second camera can bypass them.

## Run from source

Requirements:

- Python 3.10+
- Windows, macOS, or Linux for local/source use
- A modern browser

```bash
python src/burnlink.py
```

Local-only mode:

```bash
python src/burnlink.py --local
```

The portable Windows ZIP is the recommended option for Windows users.

## Privacy notes

Pending ciphertext is stored only in the running BurnLink process's memory. This does **not** mean forensic erasure. Copies may still exist in RAM, swap, crash dumps, browser internals, clipboard history, screenshots, recordings, recipient-made copies, or external services used for playback / tunneling.

BurnLink does not make a recipient anonymous, prevent recording, or guarantee deletion from every system involved.

## Third-party components

The Windows portable package includes CPython. BurnLink downloads `cloudflared` on demand. Spotify embeds use Spotify's Embed / IFrame API.

See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## Contributing

Bug reports and focused improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

For security-sensitive reports, see [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
