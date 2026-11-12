# Web Crypto Envelope

Password vaults and sealed shares use one payload format.

## Language

**Envelope**:
An AES-GCM payload serialized as three base64 fields in `iv:tag:ciphertext`
order, with a 16-byte authentication tag and possibly empty ciphertext.
