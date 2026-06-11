import { describe, it, expect } from 'vitest';
import { deriveKey, randomSalt, randomKey, encrypt, decrypt, seal, open } from './index';

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
    expect(envelope.split(':')).toHaveLength(3);
  });

  it('rejects malformed input', async () => {
    await expect(open('not-an-envelope', randomKey())).rejects.toThrow();
  });

  it('produces a UTF-8-safe round-trip', async () => {
    const { key, envelope } = await seal('emoji 🔐 and accénts');
    expect(await open(envelope, key)).toBe('emoji 🔐 and accénts');
  });
});
