# Still open / deferred

Items intentionally left for later. Each is "revisit if/when" rather than
planned work. The `export_key` non-extractable check that used to live here is
now done — covered by test #6 in `browser/tests.rb` and verified in-browser.

## 1. Generic `deep_to_ruby` converter

**State:** deliberately narrow. `Util.deep_to_ruby` handles only the five
JSON/JWK value types — array, `string`, `boolean`, `number`, `object` — and
folds everything else (`undefined` and any unexpected `typeof`) to `nil`
(`webcrypto.rb:48-50`). `null` isn't handled because standard JWK has no null
fields.

**If generalized to arbitrary JS objects, the caveats are:**
- **Functions** become `nil` (typeof `"function"` falls through).
- **`Object.keys` is own-enumerable-only** — inherited/prototype-chain and
  non-enumerable properties are silently dropped.
- **No `Date`, typed arrays, `Map`/`Set`, `Symbol`, `bigint`** handling — they
  hit the `object` branch and over-recurse or stringify wrong.
- **Circular references** infinite-loop (no cycle guard).
- **`number`** collapses integer-valued floats to `Integer` (`f == f.to_i`),
  correct for JWK but lossy/surprising for a general tool.

**Decision:** keep it JWK-scoped. Gathering ruby.wasm community input on whether
a genuine general-purpose use case exists before broadening it.

## 2. AES-KW with raw bytes

**State:** `wrap_key`/`unwrap_key` operate only on `Key` objects — `wrap_key`
takes another `Key` and returns wrapped bytes; `unwrap_key` takes bytes and
returns a fresh `Key` (`webcrypto.rb:260-280`). `format` defaults to `"raw"`
but the wrapped payload is always a `CryptoKey`, never caller-supplied bytes.

**Open question:** whether to offer AES-KW-wrap of arbitrary raw byte material.
WebCrypto itself only wraps `CryptoKey`s, so this would be an
`importKey`-then-`wrapKey` convenience shim. Deferred — no concrete use case yet.

## 3. Capability-module duplication

**State:** the capability modules are intentionally explicit rather than DRY.
The clearest repetition is `derive_key`, reimplemented four times — PBKDF2,
HKDF, ECDH, X25519 (`webcrypto.rb:508, 543, 569, 593`) — with near-identical
bodies that differ only in how each builds its `algorithm` bag. sign/verify and
encrypt/decrypt shapes recur across ECDSA/Ed25519/HMAC/RSA too.

**Decision (leaning keep-as-is):** explicit-over-shared was chosen on the
grounds that each algorithm's parameter validation and `algorithm`-bag
construction differ enough that a shared base trades readability for a thin DRY
win. Revisit if a fifth derive variant lands or the bags converge.

---

_OpenSSL backend is tracked separately and intentionally omitted here._
