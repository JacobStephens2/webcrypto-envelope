# @stephenspage/webcrypto-envelope

[![npm version](https://img.shields.io/npm/v/@stephenspage/webcrypto-envelope.svg)](https://www.npmjs.com/package/@stephenspage/webcrypto-envelope)
[![npm downloads](https://img.shields.io/npm/dm/@stephenspage/webcrypto-envelope.svg)](https://www.npmjs.com/package/@stephenspage/webcrypto-envelope)
[![CI](https://github.com/JacobStephens2/webcrypto-envelope/actions/workflows/ci.yml/badge.svg)](https://github.com/JacobStephens2/webcrypto-envelope/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/JacobStephens2/webcrypto-envelope/badge)](https://scorecard.dev/viewer/?uri=github.com/JacobStephens2/webcrypto-envelope)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A tiny, dependency-free TypeScript wrapper over the [Web Crypto API](https://developer.mozilla.org/docs/Web/API/Web_Crypto_API).
One primitive — AES-256-GCM in a compact `iv:tag:ciphertext` base64 envelope —
exposed as two patterns:

- **Password vault** — derive a key from a password (PBKDF2-SHA-256, 600k
  iterations) and encrypt/decrypt locally. For offline-first apps that sync
  ciphertext a server can't read.
- **Sealed share** — `seal()` encrypts under a fresh random key and hands the
  key back. Store the ciphertext anywhere; deliver the key out-of-band (a URL
  fragment is ideal — browsers never send it to the server) and the recipient
  `open()`s it. A **zero-knowledge shareable-link** primitive.

Runs in browsers and Node 18+ (`globalThis.crypto.subtle`). No dependencies.
Extracted from production use in [CreightonTracker](https://creightontracker.com).

Go twin: [webcrypto-envelope-go](https://github.com/JacobStephens2/webcrypto-envelope-go) -
**wire-compatible**, not just a port. An envelope produced by either
implementation opens in the other; both test suites prove it with fixtures
sealed by the opposite side. Encrypt in a browser, decrypt in a Go service -
or the reverse.

## Install

```bash
npm install @stephenspage/webcrypto-envelope
```

Releases are published to npm via GitHub Actions with [OIDC Trusted
Publishing](https://docs.npmjs.com/trusted-publishers/), so every version
carries a signed provenance statement.

If you prefer to install straight from GitHub (a `prepare` hook builds it on
install):

```bash
npm install github:JacobStephens2/webcrypto-envelope
```

## Password vault

```ts
import { deriveKey, randomSalt, encrypt, decrypt } from '@stephenspage/webcrypto-envelope';

const salt = randomSalt();                       // store alongside the user (not secret)
const key  = await deriveKey(password, salt);    // PBKDF2 → AES-256-GCM

const blob = await encrypt(JSON.stringify(data), key);   // "iv:tag:ciphertext"
// ... sync `blob` to a server that can never read it ...
const data = JSON.parse(await decrypt(blob, key));
```

## Zero-knowledge sharing

```ts
import { seal, open } from '@stephenspage/webcrypto-envelope';

// On the sharer's device:
const { key, envelope } = await seal(JSON.stringify(report));
await api.storeShare(token, envelope);                 // server holds only ciphertext
const link = `https://app.example/share/${token}#${key}`;   // key lives in the fragment

// In the recipient's browser (no account, no password):
const envelope = await api.getShare(token);            // server returns the opaque blob
const key      = location.hash.slice(1);               // never sent to the server
const report   = JSON.parse(await open(envelope, key));
```

## API

| Function | Purpose |
|---|---|
| `deriveKey(password, saltB64, { iterations? })` | PBKDF2-SHA-256 → non-extractable AES-256-GCM `CryptoKey` |
| `importKey(rawB64)` | Import a raw base64 256-bit key |
| `encrypt(plaintext, key)` → `string` | AES-256-GCM; returns `iv:tag:ciphertext` (base64) |
| `decrypt(envelope, key)` → `string` | Throws on wrong key or tampering (GCM auth) |
| `seal(plaintext)` → `{ key, envelope }` | Encrypt under a fresh random key |
| `open(envelope, keyB64)` | Decrypt a sealed payload |
| `randomKey()` / `randomSalt(bytes?)` | base64 random key / salt |

## Security notes (read these)

- **`seal`/`open`: the link *is* the credential.** Anyone with the full URL
  (including the fragment) can decrypt. Pair it with short-lived, revocable
  tokens server-side and treat the link like a password. Fragments aren't sent
  in `Referer` or server logs — don't undo that by shipping `location.href` to
  analytics.
- **Metadata isn't hidden.** GCM protects content + integrity, not the fact
  that something was stored, its size, or timing.
- **Key handling is yours.** If you persist a derived key (e.g. to survive
  reloads), you trade some at-rest protection for UX — prefer a non-extractable
  `CryptoKey` kept in memory, or re-derive per session, where you can.
- This is a thin convenience layer over a vetted primitive (AES-256-GCM), not a
  protocol. For multi-party or long-lived key management, use a real protocol.

## License

MIT © Jacob Stephens
