import { describe, it, expect } from 'vitest';
import {
  deriveKey,
  randomSalt,
  randomKey,
  encrypt,
  decrypt,
  seal,
  open,
  exportRawKey,
  importKey,
} from './index';

describe('password-derived envelope', () => {
  it('round-trips', async () => {
    const salt = randomSalt();
    const key = await deriveKey('correct horse battery staple', salt);
    const env = await encrypt('hello, health data', key);
    expect(await decrypt(env, key)).toBe('hello, health data');
  });

  it('fails with the wrong password', async () => {
    const salt = randomSalt();
    const env = await encrypt('secret', await deriveKey('right', salt));
    await expect(decrypt(env, await deriveKey('wrong', salt))).rejects.toThrow();
  });

  it('uses a fresh IV per call (ciphertext differs for identical input)', async () => {
    const key = await deriveKey('pw', randomSalt());
    expect(await encrypt('x', key)).not.toBe(await encrypt('x', key));
  });

  it('honors a custom iteration count', async () => {
    const salt = randomSalt();
    const key = await deriveKey('pw', salt, { iterations: 50_000 });
    expect(await decrypt(await encrypt('ok', key), key)).toBe('ok');
  });

  it('exports and re-imports an extractable derived key (persist-across-reload)', async () => {
    const salt = randomSalt();
    const key = await deriveKey('pw', salt, { extractable: true });
    const raw = await exportRawKey(key);
    expect(raw).toMatch(/^[A-Za-z0-9+/]+=*$/);
    const reimported = await importKey(raw);
    const env = await encrypt('persisted', key);
    expect(await decrypt(env, reimported)).toBe('persisted');
  });

  it('refuses to export a non-extractable key', async () => {
    const key = await deriveKey('pw', randomSalt());
    await expect(exportRawKey(key)).rejects.toThrow();
  });
});

describe('seal / open (zero-knowledge share)', () => {
  it('round-trips with the returned key', async () => {
    const { key, envelope } = await seal('observations json');
    expect(await open(envelope, key)).toBe('observations json');
  });

  it('cannot be opened with a different key', async () => {
    const { envelope } = await seal('observations json');
    await expect(open(envelope, randomKey())).rejects.toThrow();
  });

  it('rejects a tampered envelope', async () => {
    const { key, envelope } = await seal('data');
    const parts = envelope.split(':');
    parts[2] = randomKey(); // corrupt the ciphertext
    await expect(open(parts.join(':'), key)).rejects.toThrow();
  });
});

// Fixtures sealed by the Go twin (webcrypto-envelope-go, Go 1.26,
// crypto/cipher + crypto/pbkdf2). Opening them here is the wire-compatibility
// proof in the Go→TS direction; the Go test suite carries fixtures sealed by
// this library for the reverse.
describe('opens envelopes sealed by the Go twin', () => {
  it('opens a Go-sealed share with multi-byte UTF-8', async () => {
    const envelope =
      'dCswNnbbZyCESahF:Q/7146AV+a/4lSuya3gtuA==:gHAXbotCyU+1Xn3p+pFajdEChHy/PZ2mJA9WjvSjljjRg8QSpM8=';
    const key = 'AkNymEkG1dU790dxJM/BSi0kmeHnQ5ejOqVi05BA+fA=';
    expect(await open(envelope, key)).toBe('sealed by Go 🔐 opened by TypeScript');
  });

  it('decrypts a Go-encrypted password vault envelope', async () => {
    const key = await deriveKey('correct horse battery staple', 'c2FsdC1mb3ItaW50ZXJvcA==');
    const envelope = 'cTBHKIgKb6EHTczL:Ua7WZu6Ia20NTDbb3tH8mA==:mOom7LJgdOZACD/9AKlStQ==';
    expect(await decrypt(envelope, key)).toBe('go vault interop');
  });
});

describe('envelope format', () => {
  it('is iv:tag:ciphertext (three base64 parts)', async () => {
    const { envelope } = await seal('x');
    const parts = envelope.split(':');
    expect(parts).toHaveLength(3);
    expect(parts.map((part) => atob(part).length)).toEqual([12, 16, 1]);
    for (const part of parts) expect(btoa(atob(part))).toBe(part);
  });

  it('rejects malformed input', async () => {
    await expect(open('not-an-envelope', randomKey())).rejects.toThrow();
  });

  it('produces a UTF-8-safe round-trip', async () => {
    const { key, envelope } = await seal('emoji 🔐 and accénts');
    expect(await open(envelope, key)).toBe('emoji 🔐 and accénts');
  });
});

describe.each(['decrypt', 'open'] as const)('envelope decoding through %s', (entrypoint) => {
  async function readEnvelope(envelope: string, keyB64: string): Promise<string> {
    return entrypoint === 'decrypt'
      ? decrypt(envelope, await importKey(keyB64))
      : open(envelope, keyB64);
  }

  it.each(['', 'emoji 🔐 and accénts'])('round-trips plaintext %j', async (plaintext) => {
    const { key, envelope } = await seal(plaintext);
    if (plaintext === '') expect(envelope.split(':')[2]).toBe('');
    expect(await readEnvelope(envelope, key)).toBe(plaintext);
  });

  it('accepts omitted base64 padding', async () => {
    const { key, envelope } = await seal('hi');
    const unpadded = envelope.split(':').map((field) => field.replace(/=+$/, '')).join(':');
    expect(unpadded).not.toBe(envelope);
    expect(await readEnvelope(unpadded, key)).toBe('hi');
  });

  it('accepts ASCII whitespace inside and around base64 fields', async () => {
    const { key, envelope } = await seal('hi');
    const spaced = envelope.split(':')
      .map((field) => ` \t${field.slice(0, 2)}\n\r\f${field.slice(2)} \t`)
      .join(':');
    expect(await readEnvelope(spaced, key)).toBe('hi');
  });

  it('accepts a Web Crypto envelope with a 16-byte IV', async () => {
    const keyB64 = randomKey();
    const key = await importKey(keyB64);
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const combined = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, new TextEncoder().encode('provider-supported IV'),
    ));
    const envelope = [iv, combined.slice(-16), combined.slice(0, -16)]
      .map((bytes) => btoa(String.fromCharCode(...bytes))).join(':');
    expect(await readEnvelope(envelope, keyB64)).toBe('provider-supported IV');
  });

  it.each(['', 'one', 'one:two', 'one:two:three:four'])('preserves the field-count error for %j', async (envelope) => {
    await expect(readEnvelope(envelope, randomKey()))
      .rejects.toThrow(new Error('Invalid envelope format (expected iv:tag:ciphertext)'));
  });

  it.each([0, 1, 2])('preserves the native invalid-base64 error in field %i', async (field) => {
    const { key, envelope } = await seal('hi');
    const parts = envelope.split(':');
    parts[field] = '!';
    await expect(readEnvelope(parts.join(':'), key)).rejects.toMatchObject({
      name: 'InvalidCharacterError',
    });
  });

  it.each([0, 1, 2])('rejects independent tampering in field %i with the native authentication error', async (field) => {
    const { key, envelope } = await seal('authenticated payload');
    const parts = envelope.split(':');
    const bytes = atob(parts[field]);
    parts[field] = btoa(String.fromCharCode(bytes.charCodeAt(0) ^ 1) + bytes.slice(1));
    await expect(readEnvelope(parts.join(':'), key)).rejects.toMatchObject({
      name: 'OperationError',
    });
  });

  it.each([0, 15, 17])('rejects a resegmented %i-byte tag', async (tagBytes) => {
    const plaintext = 'enough ciphertext to move bytes across the tag boundary';
    const { key, envelope } = await seal(plaintext);
    expect(await readEnvelope(envelope, key)).toBe(plaintext);

    const [iv, tag, ciphertext] = envelope.split(':');
    const combined = atob(ciphertext) + atob(tag);
    const boundary = combined.length - tagBytes;
    const resegmentedTag = btoa(combined.slice(boundary));
    const resegmentedCiphertext = btoa(combined.slice(0, boundary));
    expect(atob(resegmentedCiphertext) + atob(resegmentedTag)).toBe(combined);

    await expect(readEnvelope(`${iv}:${resegmentedTag}:${resegmentedCiphertext}`, key))
      .rejects.toThrow('Invalid envelope format (expected a 16-byte tag)');
  });
});
