/**
 * webcrypto-envelope — a tiny, dependency-free wrapper over the Web Crypto API.
 *
 * Two patterns, one primitive (AES-256-GCM in a compact `iv:tag:ciphertext`
 * base64 envelope):
 *
 *  1. Password vault   — derive a key from a password (PBKDF2-SHA-256) and
 *                        encrypt/decrypt locally. Good for offline-first apps
 *                        that sync ciphertext the server can't read.
 *  2. Sealed share     — `seal()` encrypts under a fresh random key and hands
 *                        the key back to you. Store the ciphertext anywhere
 *                        (the server only ever holds ciphertext); deliver the
 *                        key out-of-band — e.g. in a URL fragment, which
 *                        browsers never send to the server — and the recipient
 *                        `open()`s it. This is the zero-knowledge shareable-link
 *                        primitive.
 *
 * Runs in browsers and Node 18+ (uses `globalThis.crypto.subtle`).
 * Extracted from production use in CreightonTracker.
 */

const DEFAULT_ITERATIONS = 600_000;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function webCrypto(): Crypto {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c?.subtle) throw new Error('Web Crypto API is not available in this environment');
  return c;
}

function subtle(): SubtleCrypto {
  return webCrypto().subtle;
}

function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromB64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function randomBytes(n: number): Uint8Array {
  return webCrypto().getRandomValues(new Uint8Array(n));
}

/** Random base64 salt for password derivation (default 16 bytes). */
export function randomSalt(bytes = 16): string {
  return toB64(randomBytes(bytes));
}

/** Random base64 256-bit key — e.g. for a sealed, shareable payload. */
export function randomKey(): string {
  return toB64(randomBytes(32));
}

export interface DeriveOptions {
  /** PBKDF2 iterations (default 600,000). */
  iterations?: number;
}

/** Derive a non-extractable AES-256-GCM key from a password + base64 salt (PBKDF2-SHA-256). */
export async function deriveKey(
  password: string,
  saltB64: string,
  opts: DeriveOptions = {},
): Promise<CryptoKey> {
  const material = await subtle().importKey('raw', textEncoder.encode(password) as BufferSource, 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey(
    {
      name: 'PBKDF2',
      salt: fromB64(saltB64) as BufferSource,
      iterations: opts.iterations ?? DEFAULT_ITERATIONS,
      hash: 'SHA-256',
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** Import a raw base64 256-bit key as an AES-256-GCM CryptoKey. */
export async function importKey(rawB64: string): Promise<CryptoKey> {
  return subtle().importKey('raw', fromB64(rawB64) as BufferSource, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Encrypt a UTF-8 string. Returns a compact `iv:tag:ciphertext` base64 envelope. */
export async function encrypt(plaintext: string, key: CryptoKey): Promise<string> {
  const iv = randomBytes(12);
  const buf = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, textEncoder.encode(plaintext) as BufferSource));
  const ciphertext = buf.slice(0, -16);
  const tag = buf.slice(-16);
  return `${toB64(iv)}:${toB64(tag)}:${toB64(ciphertext)}`;
}

/** Decrypt an `iv:tag:ciphertext` envelope. Throws if the key is wrong or the data was tampered with. */
export async function decrypt(envelope: string, key: CryptoKey): Promise<string> {
  const parts = envelope.split(':');
  if (parts.length !== 3) throw new Error('Invalid envelope format (expected iv:tag:ciphertext)');
  const iv = fromB64(parts[0]);
  const tag = fromB64(parts[1]);
  const ciphertext = fromB64(parts[2]);
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);
  const plain = await subtle().decrypt({ name: 'AES-GCM', iv: iv as BufferSource }, key, combined as BufferSource);
  return textDecoder.decode(plain);
}

/**
 * Seal plaintext under a fresh random key. Returns `{ key, envelope }`.
 *
 * Store `envelope` wherever you like — it is opaque ciphertext, so the storage
 * service can't read it. Deliver `key` out-of-band (a URL fragment is ideal:
 * browsers never send the fragment to the server). The recipient calls
 * `open(envelope, key)`. The storage service is therefore zero-knowledge with
 * respect to the content.
 */
export async function seal(plaintext: string): Promise<{ key: string; envelope: string }> {
  const key = randomKey();
  const envelope = await encrypt(plaintext, await importKey(key));
  return { key, envelope };
}

/** Open a sealed payload with its base64 key. */
export async function open(envelope: string, keyB64: string): Promise<string> {
  return decrypt(envelope, await importKey(keyB64));
}
