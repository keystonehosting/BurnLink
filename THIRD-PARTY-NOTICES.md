# Third-party notices

## CPython

The Windows portable build includes an unmodified portable CPython Windows runtime.

Project: https://www.python.org/

The CPython license is included inside the portable package at `runtime/LICENSE.txt`.

## cloudflared

BurnLink downloads the official Cloudflare `cloudflared` tunnel helper on demand. It is not bundled in the repository release ZIP.

Project: https://github.com/cloudflare/cloudflared

BurnLink verifies the downloaded helper against the SHA-256 digest published for the official release asset before first use.

## Spotify

When a Spotify track is included, the recipient page uses Spotify's Embed / IFrame API. Spotify is not bundled with BurnLink.

Documentation: https://developer.spotify.com/documentation/embeds
