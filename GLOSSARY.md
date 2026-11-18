# Web Crypto Envelope

Password vaults and sealed shares use one payload format.

## Language

**Envelope**:
An AES-GCM payload serialized as three base64 fields in `iv:tag:ciphertext`
order, with a 16-byte authentication tag and possibly empty ciphertext.

**Envelope key**:
A 256-bit secret AES-GCM key used to encrypt or decrypt an Envelope, represented
as a CryptoKey or base64 encoding of exactly 32 raw bytes. Extractability and
permitted usages remain properties of the CryptoKey.
