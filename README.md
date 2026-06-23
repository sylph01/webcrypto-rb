# webcrypto-rb

A Ruby-native wrapper over the browser [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
(`crypto.subtle`), for use under [ruby.wasm](https://github.com/ruby/ruby.wasm).

It wraps `CryptoKey` objects in a Ruby `Key` class, enforces key usages at the
Ruby boundary, and moves bytes across the JS boundary explicitly — the library
never guesses a string encoding for you.

## Requirements & setup

- Runs in a browser under ruby.wasm (`@ruby/3.4-wasm-wasi`). The crypto calls
  are async, so the calling Ruby must run inside `vm.evalAsync` (which sets up
  the fiber that makes `JS::Object#await` work).
- `require "js"` must be available; the library calls `require 'js'` itself.
- Web Crypto requires a [secure context](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts)
  (HTTPS or `localhost`). `randomUUID` in particular is secure-context only.

See [`browser/README.md`](browser/README.md) for a runnable harness
(`browser/index.html` scratchpad, `browser/tests.html` test suite).

```ruby
key = WebCrypto.generate_key({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
iv  = WebCrypto::Util::JSArray.to_bytes(WebCrypto.getRandomValues(12))
ct  = key.encrypt("hello".b, iv: iv)
pt  = key.decrypt(ct, iv: iv)   # => "hello"
```

## Conventions

- **Bytes are Ruby binary `String`s.** Every input/output that is "bytes"
  (plaintext, ciphertext, IVs, signatures, salts, derived material) is a Ruby
  `String`. The library does **not** apply `TextEncoder`/UTF-8 on your behalf —
  encode text yourself (e.g. `"text".b` / `str.encode("UTF-8").b`) before
  passing it in.
- **`length` is in bits** in `derive_bits` / key `length:` params, matching
  Web Crypto.
- **`verify` returns Ruby `true`/`false`.**
- **Usages are checked before the JS call.** Calling an operation the key's
  usages don't permit raises `WebCrypto::CapabilityError`, not a JS error.
- **Algorithm bags are Ruby Hashes** with symbol keys (e.g.
  `{ name: "AES-GCM", length: 256 }`); they're converted to JS internally.

## Errors

| Class | Raised when |
| --- | --- |
| `WebCrypto::Error` | Base class for all library errors. |
| `WebCrypto::CapabilityError` | Operation not permitted by the key's usages, or exporting a non-extractable key. |

`ArgumentError` / `TypeError` are raised for malformed inputs (wrong IV length,
non-`String` bytes, unsupported digest/curve/hash).

## Top-level API

### `WebCrypto.generate_key(algorithm, extractable, usages) → Key | KeyPair`

Returns a `Key` for symmetric algorithms, or a `KeyPair`
(`Struct.new(:public_key, :private_key)`) for asymmetric ones.

```ruby
aes  = WebCrypto.generate_key({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
pair = WebCrypto.generate_key({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
pair.public_key  # => WebCrypto::Key
pair.private_key # => WebCrypto::Key
```

### `WebCrypto.import_key(format, key_data, algorithm, extractable, usages) → Key`

`format` is one of `"raw"`, `"spki"`, `"pkcs8"` (then `key_data` is a byte
`String`) or `"jwk"` (then `key_data` is a Ruby `Hash`). Required for PBKDF2/HKDF
base keys, which are imported from password/secret bytes rather than generated.

```ruby
base = WebCrypto.import_key("raw", "password".b, { name: "PBKDF2" }, false, ["deriveBits"])
pub  = WebCrypto.import_key("jwk", jwk_hash, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"])
```

### `WebCrypto.digest(data, algorithm: "SHA-256") → String`

Keyless hash. `algorithm` is one of `"SHA-256"`, `"SHA-384"`, `"SHA-512"`.
**SHA-1 is intentionally not supported** (raises `ArgumentError`).

```ruby
WebCrypto::Encoding.to_hex(WebCrypto.digest("abc".b))
# => "ba7816bf...20015ad"
```

### `WebCrypto.getRandomValues(length) → JS Uint8Array`

Returns the JS `Uint8Array` (CSPRNG-filled). Convert to Ruby bytes with
`WebCrypto::Util::JSArray.to_bytes(...)`.

### `WebCrypto.randomUUID() → String`

RFC 4122 v4 UUID. Secure-context only.

## `WebCrypto::Key`

| Method | Returns |
| --- | --- |
| `#algorithm_name` | The algorithm name, e.g. `"AES-GCM"`. |
| `#usages` | Frozen `Array` of usage strings. |
| `#export_key(format)` | `"jwk"` → Ruby `Hash`; `"raw"`/`"spki"`/`"pkcs8"` → byte `String`. Raises `CapabilityError` if the key is not extractable. |

Beyond these, each `Key` gains the operations for its algorithm (mixed into its
singleton class at construction). Calling one your usages don't include raises
`CapabilityError`.

### Operations by algorithm

**Symmetric encryption**

| Algorithm | Methods |
| --- | --- |
| `AES-GCM` | `encrypt(plaintext, iv:)` / `decrypt(ciphertext, iv:)` — `iv` must be 12 bytes. |
| `AES-CTR` | `encrypt(plaintext, counter:, length: 64)` / `decrypt(ciphertext, counter:, length: 64)` — `counter` must be 16 bytes; `length` is counter bits. |
| `AES-CBC` | `encrypt(plaintext, iv:)` / `decrypt(ciphertext, iv:)` — `iv` must be 16 bytes. |

```ruby
key = WebCrypto.generate_key({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
iv  = WebCrypto::Util::JSArray.to_bytes(WebCrypto.getRandomValues(12))
ct  = key.encrypt("attack at dawn".b, iv: iv)
key.decrypt(ct, iv: iv) # => "attack at dawn"
```

**Key wrapping**

| Algorithm | Methods |
| --- | --- |
| `AES-KW` | `wrap_key(key, format: "raw") → String`<br>`unwrap_key(wrapped_key, algorithm:, usages:, extractable: true, format: "raw") → Key` |

```ruby
kek     = WebCrypto.generate_key({ name: "AES-KW", length: 256 }, true, ["wrapKey", "unwrapKey"])
dek     = WebCrypto.generate_key({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
wrapped = kek.wrap_key(dek)
restored = kek.unwrap_key(wrapped, algorithm: { name: "AES-GCM" }, usages: ["encrypt", "decrypt"])
```

**Signatures**

| Algorithm | Methods |
| --- | --- |
| `ECDSA` | `sign(data, hash: nil)` / `verify(signature, data, hash: nil)` — `hash` defaults to the curve's pairing (P-256→SHA-256, P-384→SHA-384, P-521→SHA-512). |
| `Ed25519` | `sign(data)` / `verify(signature, data)` |
| `RSASSA-PKCS1-v1_5` | `sign(data)` / `verify(signature, data)` — hash is bound to the key (JWS RS256/384/512). |
| `RSA-PSS` | `sign(data, salt_length: nil)` / `verify(signature, data, salt_length: nil)` — `salt_length` defaults to the digest length (JWS PS256/384/512). |
| `HMAC` | `sign(data)` / `verify(signature, data)` — verify delegates to constant-time `subtle.verify`. |

```ruby
pair = WebCrypto.generate_key({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"])
sig  = pair.private_key.sign("msg".b)            # signs with SHA-384
pair.public_key.verify(sig, "msg".b)             # => true
```

**Public-key encryption**

| Algorithm | Methods |
| --- | --- |
| `RSA-OAEP` | `encrypt(plaintext, label: nil)` / `decrypt(ciphertext, label: nil)` — encrypt and decrypt must use the same `label`. |

**Key derivation / agreement** (`length` in bits)

| Algorithm | Methods |
| --- | --- |
| `PBKDF2` | `derive_bits(length:, salt:, iterations:, hash: "SHA-256")`<br>`derive_key(derived_key_algorithm:, usages:, salt:, iterations:, hash: "SHA-256", extractable: true)` |
| `HKDF` | `derive_bits(length:, salt:, info:, hash: "SHA-256")`<br>`derive_key(derived_key_algorithm:, usages:, salt:, info:, hash: "SHA-256", extractable: true)` |
| `ECDH` | `derive_bits(public_key, length:)`<br>`derive_key(public_key, derived_key_algorithm:, usages:, extractable: true)` |
| `X25519` | `derive_bits(public_key, length:)`<br>`derive_key(public_key, derived_key_algorithm:, usages:, extractable: true)` |

For `ECDH`/`X25519`, `public_key` is the peer's public `Key`. `derive_bits`
returns the raw shared secret; `derive_key` returns a fresh `Key`.

```ruby
alice = WebCrypto.generate_key({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
bob   = WebCrypto.generate_key({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
secret = alice.private_key.derive_bits(bob.public_key, length: 256) # == bob ⨯ alice
```

## Helpers

### `WebCrypto::Encoding`

Byte `String` ↔ text. Uses `pack`/`unpack` (no `base64` gem dependency); base64
is strict and unwrapped.

| Method | Description |
| --- | --- |
| `.to_hex(bytes) → String` | Lowercase hex. |
| `.from_hex(hex) → String` | Bytes from hex. |
| `.to_base64(bytes) → String` | Strict base64, no newlines. |
| `.from_base64(str) → String` | Bytes from strict base64. |

### `WebCrypto::Util::JSArray`

Bridges Ruby byte `String`s and JS typed arrays. Every byte (including ≥ 0x80)
crosses unchanged — never via `TextEncoder`.

| Method | Description |
| --- | --- |
| `.to_bytes(js_array) → String` | JS `Uint8Array`/`ArrayBuffer` → Ruby bytes. |
| `.from_bytes(bytes) → JS Uint8Array` | Ruby bytes → JS `Uint8Array`. |
| `.to_a(js_array) → Array<Integer>` | JS typed array → array of byte values. |

### `WebCrypto::Util.deep_to_ruby(value)` / `.deep_to_js(value)`

Recursive JS ↔ Ruby conversion for JWK-shaped structures (Hashes, Arrays,
strings, booleans, numbers). Used by `export_key("jwk")` / `import_key("jwk", …)`.
Scoped to JSON-shaped data — see the deferred notes for the caveats on generic
objects.

## Algorithm support

generate/import · encrypt/decrypt · sign/verify · wrap/unwrap · derive

| Algorithm | Operations |
| --- | --- |
| AES-GCM, AES-CTR, AES-CBC | encrypt / decrypt |
| AES-KW | wrapKey / unwrapKey |
| ECDSA, Ed25519, RSASSA-PKCS1-v1_5, RSA-PSS | sign / verify |
| HMAC | sign / verify |
| RSA-OAEP | encrypt / decrypt |
| PBKDF2, HKDF | deriveBits / deriveKey |
| ECDH, X25519 | deriveBits / deriveKey |
| SHA-256 / SHA-384 / SHA-512 | digest (keyless) |

Actual availability depends on the host browser's Web Crypto implementation
(e.g. Ed25519/X25519 require a recent browser).
