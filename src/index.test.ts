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

const invalidKeyError = new Error('Invalid key (expected a 256-bit AES-GCM key)');

async function nativeEnvelope(plaintext: string, key: CryptoKey, iv = crypto.getRandomValues(new Uint8Array(12))): Promise<string> {
  const combined = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext),
  ));
  return [iv, combined.slice(-16), combined.slice(0, -16)]
    .map((bytes) => btoa(String.fromCharCode(...bytes))).join(':');
}

describe('Envelope key transfer', () => {
  it('creates fresh random 32-byte keys in padded base64', () => {
    const first = randomKey();
    const second = randomKey();
    expect(first).not.toBe(second);
    for (const raw of [first, second]) {
      expect(atob(raw)).toHaveLength(32);
      expect(raw).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    }
  });

  it.each([0, 16, 24, 31, 33])('rejects %i-byte raw keys through import and open', async (bytes) => {
    const raw = btoa('\0'.repeat(bytes));
    const { envelope } = await seal('valid Envelope');
    await expect(importKey(raw)).rejects.toStrictEqual(invalidKeyError);
    await expect(open(envelope, raw)).rejects.toStrictEqual(invalidKeyError);
  });

  it.each([128, 192])('rejects actual %i-bit export material even if metadata reports 256 bits', async (length) => {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length }, true, ['encrypt', 'decrypt']);
    Object.assign(key.algorithm, { length: 256 });
    await expect(exportRawKey(key)).rejects.toStrictEqual(invalidKeyError);
  });

  it.each(['padded', 'unpadded', 'ASCII whitespace'])('transfers an external AES-256-GCM key with %s base64', async (form) => {
    const external = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const raw = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.exportKey('raw', external))));
    expect(atob(raw)).toHaveLength(32);
    expect(raw).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect(await exportRawKey(external)).toBe(raw);
    const formatted = form === 'unpadded' ? raw.replace(/=+$/, '')
      : form === 'ASCII whitespace' ? ` \t${raw.slice(0, 2)}\n\r\f${raw.slice(2)} \t` : raw;
    const imported = await importKey(formatted);
    expect(imported.type).toBe('secret');
    expect(imported.algorithm).toEqual({ name: 'AES-GCM', length: 256 });
    expect(imported.extractable).toBe(false);
    expect(imported.usages).toEqual(['encrypt', 'decrypt']);
    const envelope = await encrypt('external key transfer', external);
    expect(await decrypt(envelope, external)).toBe('external key transfer');
    expect(await decrypt(envelope, imported)).toBe('external key transfer');
    expect(await open(envelope, formatted)).toBe('external key transfer');
  });

  it.each(['!', 'A'])('preserves native invalid-base64 failures for %j through import and open', async (raw) => {
    const { envelope } = await seal('valid Envelope');
    await expect(importKey(raw)).rejects.toMatchObject({ name: 'InvalidCharacterError' });
    await expect(open(envelope, raw)).rejects.toMatchObject({ name: 'InvalidCharacterError' });
  });
});

describe.each([128, 192])('external AES-GCM-%i keys', (length) => {
  it.each(['encrypt', 'decrypt', 'exportRawKey'] as const)('rejects the key through %s', async (operation) => {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length }, true, ['encrypt', 'decrypt']);
    const envelope = await nativeEnvelope('native payload', key);
    const result = operation === 'encrypt'
      ? encrypt('native payload', key)
      : operation === 'decrypt' ? decrypt(envelope, key) : exportRawKey(key);
    await expect(result).rejects.toStrictEqual(invalidKeyError);
  });
});

describe('unrelated CryptoKeys', () => {
  it.each(['AES-CBC', 'HMAC'] as const)('rejects %s keys through encrypt, decrypt and export', async (name) => {
    const key = await crypto.subtle.importKey(
      'raw', new Uint8Array(32),
      name === 'HMAC' ? { name, hash: 'SHA-256' } : { name },
      true, name === 'HMAC' ? ['sign'] : ['encrypt', 'decrypt'],
    );
    const { envelope } = await seal('valid Envelope');
    await expect(exportRawKey(key)).rejects.toStrictEqual(invalidKeyError);
    await expect(encrypt('payload', key)).rejects.toStrictEqual(invalidKeyError);
    await expect(decrypt(envelope, key)).rejects.toStrictEqual(invalidKeyError);
  });

  it.each(['publicKey', 'privateKey'] as const)('rejects an ECDSA %s through encrypt, decrypt and export', async (type) => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const { envelope } = await seal('valid Envelope');
    await expect(exportRawKey(pair[type])).rejects.toStrictEqual(invalidKeyError);
    await expect(encrypt('payload', pair[type])).rejects.toStrictEqual(invalidKeyError);
    await expect(decrypt(envelope, pair[type])).rejects.toStrictEqual(invalidKeyError);
  });
});

describe('external Envelope key permissions', () => {
  it('supports encrypt-only keys and preserves native decryption permission failures', async () => {
    const raw = new Uint8Array(32);
    const encryptOnly = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const both = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
    const envelope = await encrypt('encrypt-only key', encryptOnly);
    expect(await decrypt(envelope, both)).toBe('encrypt-only key');
    await expect(decrypt(envelope, encryptOnly)).rejects.toMatchObject({ name: 'InvalidAccessError' });
  });

  it('supports decrypt-only keys and preserves native encryption permission failures', async () => {
    const raw = new Uint8Array(32);
    const decryptOnly = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const encryptOnly = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
    const envelope = await nativeEnvelope('decrypt-only key', encryptOnly);
    expect(await decrypt(envelope, decryptOnly)).toBe('decrypt-only key');
    await expect(encrypt('forbidden', decryptOnly)).rejects.toMatchObject({ name: 'InvalidAccessError' });
  });

  it('preserves the native export failure for a conforming non-extractable external key', async () => {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const nativeError = await crypto.subtle.exportKey('raw', key).catch((error) => error);
    await expect(exportRawKey(key)).rejects.toMatchObject({ name: nativeError.name, message: nativeError.message });
  });
});

describe('Envelope key validation order', () => {
  it.each([
    ['not-an-envelope', { name: 'Error', message: 'Invalid envelope format (expected iv:tag:ciphertext)' }],
    ['AAAAAAAAAAAAAAAA::', { name: 'Error', message: 'Invalid envelope format (expected a 16-byte tag)' }],
    ['!:AAAAAAAAAAAAAAAAAAAAAA==:', { name: 'InvalidCharacterError' }],
  ] as const)('decodes %j before checking a nonconforming CryptoKey', async (envelope, expected) => {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['decrypt']);
    await expect(decrypt(envelope, key)).rejects.toMatchObject(expected);
  });

  it('imports the key before decoding the Envelope through open', async () => {
    await expect(open('not-an-envelope', btoa('\0'.repeat(16)))).rejects.toStrictEqual(invalidKeyError);
    await expect(open('not-an-envelope', '!')).rejects.toMatchObject({ name: 'InvalidCharacterError' });
  });
});

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
    const envelope = await nativeEnvelope('provider-supported IV', key, iv);
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
