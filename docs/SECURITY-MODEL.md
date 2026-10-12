# BurnLink security model

This document describes what BurnLink 3.0 is designed to protect and where its guarantees stop.

## Goals

BurnLink is designed to:

- avoid storing pending plaintext in the Python server,
- permit only one successful encrypted-payload retrieval,
- prevent ordinary link previews from consuming a message,
- make an optional passcode cryptographically relevant to decryption,
- provide a sender-side distinction between retrieval and confirmed rendering,
- keep installation requirements on the sender side only.

## Message encryption

The sender browser generates a random message key and encrypts the message payload using AES-256-GCM.

The encrypted payload can include:

- text,
- image data,
- attached audio,
- Spotify URL,
- media start time,
- recipient privacy settings.

The message key is placed in the URL fragment. Fragments are handled by the browser and are not included in normal HTTP requests to the server.

## Passcodes

If a passcode is enabled, PBKDF2-SHA-256 with 250,000 iterations derives material in the browser. Part of that material wraps the random message key with AES-GCM. Separate derived material is used as a verifier for server-side attempt counting.

The raw passcode is not sent to the Python server.

After five incorrect attempts, the pending link is disabled.

## One-use retrieval

Opening the landing page does not retrieve the encrypted payload.

The encrypted payload is consumed only by the explicit open operation. The server removes the stored ciphertext before returning it, making retrieval atomic with respect to competing open attempts.

A network failure during the successful retrieval can therefore cause a message to be lost. This is an intentional tradeoff in favor of one-use semantics.

## Viewed receipts

A payload retrieval changes state to Opened. The recipient page changes it to Viewed only after successful decryption and rendering and after sending a one-time display receipt.

This is not a non-repudiation mechanism. A modified recipient client can suppress or alter client-side behavior.

## Public tunnel

The portable Windows build uses Cloudflare Quick Tunnels. This means traffic is transported through Cloudflare infrastructure before reaching the sender's local BurnLink instance.

BurnLink does not claim that Quick Tunnels provide anonymity or guaranteed uptime.

## Out of scope

BurnLink cannot guarantee prevention of:

- screenshots,
- operating-system or browser recording,
- photography with another device,
- browser extensions or modified clients,
- memory / swap / crash-dump recovery,
- recipient transcription or manual copying,
- external-service logging by Cloudflare or Spotify,
- endpoint compromise on the sender or recipient device.

Any visible or audible content can ultimately be captured by a recipient who controls their device.
