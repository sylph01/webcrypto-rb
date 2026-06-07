# Design Decisions — Review Log

A record of the design choices made during the WebCrypto-backend build-out where
there was a genuine fork in the road. For each: what was chosen, the
alternatives considered, and why. Commit hashes are included for tracing.

---

## 1. API surface & architecture

### 1.1 Class-based `Key` with a private `@js`  (`0955bf3`)
- **Chosen:** A real `WebCrypto::Key` class holding the JS `CryptoKey` in a
  private `@js`; per-algorithm capability modules live under a `Capabilities`
  namespace and are mixed into each key's singleton class.
- **Alternatives:** Keep the earlier `extend`-onto-`JS::Object` pattern (exposes
  the JS handle as the public surface); or define every op directly on `Key`
  with internal algorithm dispatch (loses the localized per-algorithm modules).
- **Why:** Hides the JS handle from callers (the core design rule) and gives a
  stable Ruby-native surface for the eventual OpenSSL backend, while reusing the
  existing per-algorithm modules with minimal churn.

### 1.2 `protected attr_reader :js`  (`0955bf3`)
- **Chosen:** Expose `@js` to *other* `Key`s via a `protected` reader, needed by
  AES-KW `wrap_key` and ECDH/X25519 derive (which must hand a peer/target key's
  JS handle to `subtle`).
- **Alternatives:** Make AES-KW/derive take raw key bytes instead (avoids any
  handle exposure).
- **Why:** Reading another `Key`'s handle is the natural model; `protected`
  keeps it off the public surface. **You flagged you may revisit the raw-bytes
  approach for AES-KW later.**

### 1.3 Capability enforcement → `CapabilityError`  (`e7614e6`)
- **Chosen:** Mix in *all* of an algorithm's capability modules, and have each
  method call `require_usage!` first, raising `WebCrypto::CapabilityError` when
  the key's usages don't permit the op.
- **Alternatives:** Keep mixing in only the permitted modules (a disallowed op
  is then a bare `NoMethodError`).
- **Why:** A clear, early Ruby error mirroring WebCrypto's `InvalidAccessError`.
  Note the deliberate split: missing-usage-on-a-supported-op → `CapabilityError`;
  op the algorithm doesn't support at all (e.g. `encrypt` on ECDSA) →
  `NoMethodError`, matching WebCrypto's own distinction.

### 1.4 `usages` memoization  (`d23f0ca`)
- **Chosen:** Snapshot usages once at construction into a frozen `@usages`.
- **Alternatives:** Read from JS on every call.
- **Why:** A `CryptoKey`'s usages are immutable, so the snapshot can never go
  stale; frozen so a caller can't mutate the shared array and skew later checks.
  Kept as a **separate commit** at your request.

### 1.5 Bytes-only public API  (`ad5c5eb`, `eef194b`)
- **Chosen:** Every crypto op takes Ruby byte `String`s and returns Ruby byte
  `String`s; conversion to/from `Uint8Array` happens inside via per-byte
  construction (`from_bytes`/`to_bytes`).
- **Alternatives:** The original `TextEncoder` path (silently UTF-8-encoded
  input, corrupting any byte ≥ 0x7F); or returning raw `ArrayBuffer`/`JS::Object`.
- **Why:** Correctness (no silent corruption of key material) and the rule that
  `JS::Object` never crosses the public boundary. `from_bytes` also type-checks,
  turning bad input into a clear `TypeError` instead of an opaque `.await` failure.

### 1.6 `WebCrypto::Encoding` — base64 via `pack`/`unpack`  (`e3d12d6`)
- **Chosen:** `to_base64`/`from_base64` use `pack("m0")`/`unpack1("m0")` (strict,
  unwrapped), not the `base64` gem.
- **Alternatives:** `Base64.strict_encode64`/`strict_decode64` (as the original
  design notes suggested).
- **Why:** `base64` became a bundled gem in Ruby 3.4 and isn't guaranteed present
  in the ruby.wasm build; `pack("m0")` is byte-identical, dependency-free, and
  consistent with the hex helpers. (Also dropped the unused `to_hex_array` in the
  same commit.)

### 1.7 Explicit per-algorithm modules over a shared abstraction
- **Chosen:** AES-GCM/CTR/CBC and ECDH/X25519 repeat near-identical bodies
  rather than sharing a generic encrypt/derive helper.
- **Alternatives:** Factor the common shape into one helper.
- **Why:** Matches the codebase's existing explicit style and keeps each
  algorithm's params/quirks localized and readable. **Worth revisiting if the
  duplication becomes a maintenance cost.**

---

## 2. Cryptographic defaults

### 2.1 IV validation lives per-algorithm  (`87b29fe`)
- **Chosen:** Each algorithm module owns its IV/counter contract
  (`AESGCM::IV_LENGTH = 12`, `AESCBC::IV_LENGTH = 16`, `AESCTR::COUNTER_LENGTH`),
  validating and raising before any JS call.
- **Alternatives:** A single shared IV validator.
- **Why:** IV length is algorithm-specific (GCM wants 12 for the fast path; CBC
  wants 16), so the contract belongs with the algorithm. New variants add their
  own without touching others.

### 2.2 ECDSA hash derived from the key's curve  (`795805a`)
- **Chosen:** When `hash:` is omitted, derive it from the key's `namedCurve`
  (RFC 7518 pairing: P-256→SHA-256, P-384→SHA-384, P-521→SHA-512); explicit
  override still honored. An **unrecognized curve raises** rather than defaulting.
- **Alternatives:** Keep the hardcoded SHA-256 default; or fall back to SHA-256
  for unknown curves.
- **Why:** A P-384 key signing with SHA-256 was wrong. `namedCurve` is a required
  member of `EcKeyGenParams`, so any working key has a known curve — an unknown
  one signals something unexpected and should fail loudly. (You chose the raise
  after we confirmed the curve is always present.)

### 2.3 RSA-PSS `saltLength` default  (`f0bf97c`)
- **Chosen:** Default `salt_length` to the key hash's digest length
  (SHA-256→32, 384→48, 512→64) — the salt-equals-digest convention of JWS
  PS256/384/512; explicit override honored; unsupported hash raises.
- **Alternatives:** Max salt length (`emLen − hLen − 2`); or require explicit
  `salt_length:` on every call.
- **Why:** Most use will be JWS-related, where this convention is expected. Max
  salt isn't what JWS verifiers expect; requiring it everywhere is poor ergonomics
  given a near-universal convention exists. **(Your call — "most use cases will
  be JWS.")**

### 2.4 SHA-1 deliberately excluded from `digest`  (`2c065f8`)
- **Chosen:** `digest` allow-lists SHA-256/384/512; SHA-1 (and anything else)
  raises `ArgumentError`.
- **Alternatives:** Pass the algorithm through to WebCrypto (which supports SHA-1).
- **Why:** SHA-1 isn't collision-resistant; not surfacing it in the default API
  matches the original design stance.

### 2.5 RSASSA-PKCS1-v1_5 included  (`7e73370`)
- **Chosen:** Add it (sign/verify), same shape as Ed25519.
- **Context:** You asked whether it was omitted for security. It wasn't — it's
  the JWS RS256/384/512 family and is fine for signatures. The Bleichenbacher
  history is about PKCS#1 v1.5 *encryption* (which WebCrypto doesn't even expose;
  RSA encryption is RSA-OAEP only).

### 2.6 RSA-OAEP `label` optional, omitted by default  (`20739d8`)
- **Chosen:** `encrypt`/`decrypt` take an optional `label:`; when omitted the bag
  is just `{name: "RSA-OAEP"}`. Encrypt and decrypt must agree on the label.
- **Why:** Matches the common case (no label) while supporting associated data.

### 2.7 `derive_bits` `length:` is a required keyword  (`1ef914e`–`2e78ca6`)
- **Chosen:** All four derive algorithms require an explicit `length:`.
- **Alternatives:** Default ECDH/X25519 to the curve's natural output (256 bits).
- **Why:** Length is a protocol parameter the caller should state; consistent
  across the group, and avoids relying on inconsistent null-length browser support.

---

## 3. ruby.wasm boundary

### 3.1 `deep_to_ruby` is a JSON-value converter, not generic  (`08c800a`, `fb805b4`)
- **Chosen:** A narrow recursive converter handling array/string/boolean/number/
  object, scoped to JWK-shaped data. JS→Ruby type probe: `Array.isArray` then
  `typeof` (JS-side, because `JS::Object` is a `BasicObject`).
- **Alternatives:** A fully generic JS→Ruby converter.
- **Why:** JWK needs only the JSON value types. A generic version has real
  caveats — `null` (crashes `Object.keys`), functions/symbol/bigint (silently
  dropped), Date/Map/Set/typed-arrays (convert to `{}`/index-hash), cycles
  (infinite recursion), own-enumerable-only, NaN/Infinity (`to_i` raises),
  >2^53 precision. **You're gathering real use cases from the ruby.wasm community
  before deciding whether to build the generic version.**

### 3.2 `export_key` extractability check → `CapabilityError`  (`fb805b4`)
- **Chosen:** `export_key` raises `CapabilityError` if the key isn't extractable,
  before the JS call.
- **Alternatives:** Let WebCrypto throw its own `InvalidAccessError`.
- **Why:** Consistent with the `require_usage!` pattern — fail early with a clear
  Ruby error.

### 3.3 `import_key` supports byte formats; JWK deep-converted  (`a8fe9c3`, `fb805b4`)
- **Chosen:** `raw`/`spki`/`pkcs8` take Ruby bytes (`from_bytes`); `jwk` takes a
  Ruby Hash (`deep_to_js`). Added as a prerequisite because PBKDF2/HKDF base keys
  can only be imported (no `generateKey` for them).

### 3.4 `digest` algorithm passed as a bare string  (`2c065f8`)
- **Chosen:** `subtle.digest("SHA-256", bytes)` (string), not `{name: ...}`.
- **Why:** The spec accepts a string; the Ruby `String` auto-converts cleanly,
  and there are no other params to bag up.

---

## 4. Tooling & workflow

### 4.1 Browser test env serves the repo root  (`64525ae`)
- **Chosen:** `ruby -run -e httpd . -p 8000` (repo root) so pages under `/browser/`
  can fetch `../webcrypto.rb`; open `/browser/index.html`.
- **Alternatives:** The notes' `httpd browser` (docroot = `browser/`, which can't
  reach the library); or a `browser/webcrypto.rb` symlink.
- **Why:** The docroot must be able to serve the library. (Symlink offered as an
  alternative if you prefer the literal command.)

### 4.2 `require "js/promise"` removed  (`c5bbc2e`)
- **Context:** The pinned ruby.wasm build (`@ruby/3.4-wasm-wasi@2.7.1`) ships no
  separate `js/promise`; `JS::Object#await` works from `require "js"` alone under
  `vm.evalAsync`. The original design note about `js/promise` is stale for this
  version.

### 4.3 Commit discipline
- **Chosen:** One focused commit per accepted change; split unrelated changes
  (e.g. TextEncoder fix vs IV validation were separate); stage explicit paths and
  check `git status` before committing.
- **Context:** After `CLAUDE.md` was once swept into a commit accidentally, the
  rule is to never blind-chain `git add … && git commit`. `CLAUDE.md` is kept
  untracked (you maintain it on a separate branch).

---

## 5. Still open / deferred (your call later)

- **Generic `deep_to_ruby`** — pending real use cases from the ruby.wasm community
  (§3.1).
- **AES-KW with raw bytes** instead of the `protected :js` handle model (§1.2).
- **OpenSSL backend** — you have separate plans; the `Key` class is the stable,
  JS-hidden surface it's meant to plug into.
- **Verify the `export_key` non-extractable test** in-browser (the two main JWK
  round-trips are confirmed green).
- **Shared abstraction** for the duplicated AES and ECDH/X25519 bodies, if the
  duplication ever bites (§1.7).
