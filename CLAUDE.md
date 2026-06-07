# WebCrypto Ruby Wrapper — Design Notes

This document captures the design decisions, technical rationale, and known
pitfalls discovered while building a Ruby wrapper around the Web Crypto API,
running on `ruby.wasm` in browsers. It is intended both as a starting context
for future Claude sessions and as a reference for the author when picking the
project back up after a break.

## Project Goal

The project is a Ruby library that exposes Web Crypto API functionality
(symmetric encryption, signing, key derivation, hashing) through an idiomatic
Ruby surface. It currently targets `ruby.wasm` running in browsers, where
`crypto.subtle` is reachable via the JavaScript bridge. The eventual goal is to
support a second backend — native CRuby with OpenSSL — behind the same public
API, so that the same Ruby code runs unchanged in browser-WASM and
native-server environments.

This backend-portability goal drives almost every design decision in the
library. The public API must not leak anything specific to JavaScript,
WebAssembly, or any particular crypto provider. Callers should be able to
write Ruby code today against the WebCrypto backend and have it continue
working when an OpenSSL backend ships, with no changes beyond updating the
gem.

## Design Principles

The most important rule is that the JS↔Ruby boundary lives *inside* the
library, never at its surface. Every public method takes Ruby types and
returns Ruby types. `JS::Object` references are an implementation detail of
the WebCrypto backend; callers must never need to construct, inspect, or pass
one. This rule applies even when it costs ergonomics — for example, the
library prefers to pay the per-byte boundary-crossing cost on result
conversion rather than return a `JS::Object` that callers would have to
unwrap themselves.

The second rule is that the library does not pick byte representations on the
caller's behalf. Cryptographic operations act on bytes. If a caller wants to
sign a string, they must explicitly decide which bytes that string corresponds
to (UTF-8, UTF-16, ASCII, Latin-1, or any canonical encoding their protocol
specifies) and pass those bytes in. The library refuses to offer a convenience
overload that silently encodes a Ruby `String` as UTF-8, because doing so
would create signatures that mysteriously fail to verify against systems that
chose differently. Interop with services written in other languages depends
on being explicit about this.

The third rule is that capability enforcement at the Ruby level mirrors
capability enforcement at the WebCrypto level. A key generated with `usages:
["sign"]` will refuse to encrypt at the Ruby boundary with a clear error,
just as WebCrypto itself would reject the same call with `InvalidAccessError`.
This catches misuse earlier and with better diagnostics.

The fourth rule is that the library validates types and encodings at the
boundary and produces clear Ruby errors. Callers should never see a JS stack
trace bubbling up from a `.await` call when the actual problem is that they
passed a Ruby `String` where bytes were expected. Type checks at entry are
cheap and pay back enormously in debuggability.

## Architecture

The public surface is built around a small number of Ruby classes. The
central one is `WebCrypto::Key`, which wraps a JS `CryptoKey` in a private
`@js` instance variable. Methods like `encrypt`, `decrypt`, `sign`, `verify`,
`derive_key`, and `export_raw` live on this class. The class does runtime
capability checks against the key's stored `usages` array, raising
`WebCrypto::CapabilityError` when a method is called on a key that doesn't
permit the corresponding operation.

For asymmetric algorithms, `generateKey` produces a key pair rather than a
single key. This is exposed as `WebCrypto::KeyPair`, a small struct-like
class with `public_key` and `private_key` attributes, each holding a
`WebCrypto::Key`. The library detects which shape WebCrypto returned by
checking `result[:constructor][:name]` — `"CryptoKey"` for symmetric keys,
`"Object"` for the dictionary returned for key pairs.

Earlier iterations of the design used Ruby's `extend`-with-modules pattern to
mix encrypt/decrypt/sign/verify capabilities onto raw `JS::Object` references
at runtime. That approach was abandoned for two reasons. First, `JS::Object`
inherits from `BasicObject` rather than `Object`, so `extend` is not
available on it — the workaround `(class << obj; include Mod; end)` does
work, but at a syntax cost. Second, and more important, the goal of hiding
the JS handle from callers conflicts with the `extend` approach, which
inherently exposes the underlying `JS::Object` as the public API surface.
The class-based design makes `@js` private and gives the library a stable
Ruby-native surface that can swap backends without callers noticing.

A `WebCrypto::Encoding` module provides hex and base64 helpers. These are
thin wrappers over `[bytes].pack("H*")` / `unpack1("H*")` and `Base64`, with
the wrinkle that base64 encoding uses `strict_encode64` (no embedded
newlines) rather than the MIME-style `encode64`. The reason: WebCrypto's
`atob` and equivalent APIs tolerate but don't require whitespace, and
unwhitespaced base64 is what every other modern API and storage format
expects. Centralizing this choice in one module prevents subtle interop bugs
later.

Internal utilities live in `WebCrypto::Util`. The most important is
`js_obj(hash)`, which builds a real JS object from a Ruby hash by creating
`JS.global[:Object].new` and assigning properties one by one. Ruby's
auto-conversion of `Hash` to a JS plain object only works when all values are
primitives — as soon as any value is a `JS::Object` (like a `Uint8Array` for
an IV), the auto-conversion breaks down. `js_obj` handles both cases
uniformly because per-property assignment goes through `JS::Object#[]=`,
which does invoke per-value conversion correctly.

A separate `WebCrypto::Util::JSArray` namespace holds the helpers that
convert between JS typed arrays / array buffers and Ruby byte strings. The
key insight is that `ArrayBuffer` and `Uint8Array` need different handling:
`ArrayBuffer` has no indexed access and no `length` property (it has
`byteLength`), so it must be wrapped in a `Uint8Array` view before any
byte-level reads. The library checks `constructor.name` to decide whether to
wrap. This wrapping is invisible to callers; they always get a Ruby binary
`String` back.

The backend split is achieved by a thin layer that selects between
`WebCrypto::Backends::WebCrypto` (the ruby.wasm/browser path) and an eventual
`WebCrypto::Backends::OpenSSL` (native CRuby). Backend selection happens at
load time based on whether `JS.global` is defined and `RUBY_PLATFORM`
includes `wasm`. The classes (`Key`, `KeyPair`) live in the top-level
namespace; only the operations that actually touch crypto primitives are
backend-specific.

## The ruby.wasm Boundary

Understanding how data crosses between Ruby and JavaScript through ruby.wasm
is essential to working on this library. Several rules and gotchas apply.

`JS::Object` inherits from `BasicObject`, not `Object`. This means most of
Ruby's "every object responds to X" assumptions are wrong for JS::Objects.
Calling `extend`, `respond_to?`, `is_a?`, `inspect`, `class`, or `tap` on a
`JS::Object` falls through to `method_missing`, which dispatches to JS and
fails (often loudly) because there's no JS method with that name. The
practical implication is that anywhere code might receive a `JS::Object`, it
must use either property access (`obj[:foo]`) or the singleton class
manipulation syntax (`class << obj; ...; end`), never the Ruby reflection
methods.

`JS::Object#inspect` has a particularly nasty failure mode for primitives.
When a JS function returns a string, number, or boolean primitive (as
`crypto.randomUUID()` does), ruby.wasm wraps it in a `JS::Object`. The
wrapper's `inspect` method tries to call `Reflect.has(target, ...)` to
discover available properties, which throws a TypeError because `Reflect.has`
requires `target` to be an object, not a primitive. The error message ("got
\"87557c40-...\"") confusingly contains the actual value. The fix is always
to convert primitive-wrapping `JS::Object`s to Ruby types immediately:
`.to_s` for strings, `.to_i` / `.to_f` for numbers, `== JS::True` for
booleans.

The Hash-to-JS-Object conversion at the boundary is partial. Ruby `Hash`
auto-converts to a JS plain object when used as a method argument, but only
when every value in the hash is itself a primitive (string, number, boolean,
nil, array of these, or nested hash of these). As soon as one value is a
`JS::Object` — for instance, an IV stored as a `Uint8Array` — the
auto-conversion silently fails or produces a malformed object that WebCrypto
rejects. This is why the library uses `Util.js_obj(hash)` everywhere that
builds an options bag, rather than passing Ruby hashes directly.

Method dispatch on `JS::Object` uses `method_missing` to forward to JS, with
ergonomic shortcuts: trailing `?` becomes a JS predicate call with boolean
coercion, snake_case is left alone (no automatic camelCase translation),
and `new` becomes the JavaScript `new` operator. So
`JS.global[:Uint8Array].new(16)` constructs a `Uint8Array` of length 16, and
`JS.global[:crypto][:subtle].encrypt(...)` calls the JS method as written.

Promises returned from JS need `require "js/promise"` to enable
`JS::Object#await`. Without that require, the only way to handle async results
is `.then { |result| ... }` callbacks, which fragment the code. With it,
synchronous-looking Ruby code that calls `.await` works because ruby.wasm
runs the script inside a fiber and can suspend it while the promise resolves.
`vm.evalAsync(code)` from the JavaScript side sets up the necessary fiber
context; in the browser scratchpad, top-level `.await` works because of this.

JS booleans returned to Ruby are `JS::Object` wrappers, not Ruby `true` /
`false`. Bare `if js_bool` is always truthy, which leads to silent bugs.
Always compare against `JS::True` (or `JS::False`) explicitly. The library
internalizes this by converting at the boundary — for example, in `verify`,
the result of `subtle.verify(...).await` is compared to `JS::True` so the
return value is a real Ruby boolean.

Boundary crossings have per-call overhead. For a 32-byte AES key, the
per-byte loop (`length.times.map { |i| arr[i].to_i }`) is fine — 32
boundary crossings, microseconds. For a 100KB payload, the same loop is
100,000 boundary crossings and noticeably slow. The library should be
careful to use bulk operations (e.g., `TextDecoder.decode` on the JS side,
or base64-shuttle via `atob`/`btoa`) for anything beyond a few hundred
bytes. As a practical rule, anything sized in "keys, IVs, signatures, short
messages" can use the simple loop; anything sized in "files, large
payloads" should bulk-convert via JS-side helpers.

## WebCrypto API Mechanics

WebCrypto's `subtle` methods are async and return Promises that resolve to
either `ArrayBuffer` (for byte-producing operations like `encrypt`,
`decrypt`, `sign`, `digest`, `exportKey` with format `"raw"`) or to
structured objects (`CryptoKey` for `generateKey` of symmetric algorithms,
`CryptoKeyPair`-shaped object for asymmetric, `JsonWebKey` dict for
`exportKey` with format `"jwk"`).

`ArrayBuffer` is opaque from Ruby. It has `byteLength` but no `length`, and
no indexed access — reading `buf[0]` returns `undefined`, which becomes `0`
after `.to_i`. Code that tries to iterate an `ArrayBuffer` as if it were a
`Uint8Array` will silently produce an empty result. The library always
wraps `ArrayBuffer` results in `Uint8Array` before reading bytes:
`JS.global[:Uint8Array].new(arr_buffer)`. The `Util::JSArray.view` helper
encapsulates this discrimination by checking `constructor.name`.

`ArrayBuffer` is transparent to other WebCrypto APIs, though. You can pass
the `ArrayBuffer` returned by `encrypt` directly to `decrypt` without
wrapping. The asymmetry is: WebCrypto APIs accept `BufferSource` (either
`ArrayBuffer` or any typed-array view), so they don't care. Only Ruby code
that wants to read bytes needs the view.

`TextEncoder` and `TextDecoder` are for converting between JS strings and
UTF-8 bytes. They are not for converting between bytes and "strings in
general." `TextEncoder.encode(jsString)` produces UTF-8 bytes of the string
content; this is lossless for any input that originated as a Ruby `String`.
`TextDecoder.decode(buffer)` interprets bytes as UTF-8 and replaces invalid
sequences with U+FFFD by default. For random bytes (keys, signatures,
ciphertext, digests), almost every byte sequence contains invalid UTF-8, so
`TextDecoder` silently corrupts the data. The library never uses
`TextDecoder` for key material; it uses `pack("C*")` to produce a binary
Ruby `String` whose bytes match the source exactly.

In the reverse direction, the library never uses `TextEncoder` to construct
byte material for crypto inputs. A Ruby binary string of random bytes,
passed through `TextEncoder`, would be interpreted as a JS string (after
boundary conversion) and then re-encoded as UTF-8, with each non-ASCII byte
expanding to two or more bytes. A 32-byte AES key fed through this path
becomes 40-something bytes of garbage. The library uses per-byte
construction (`each_byte.with_index { |b, i| arr[i] = b }`) when bytes need
to enter JS as a `Uint8Array`.

The `iv` and `data` arguments to encrypt/decrypt must be `BufferSource`
values. The library accepts Ruby binary `String` from callers and converts
to `Uint8Array` internally. Passing a raw Ruby `String` directly to
`subtle.encrypt` results in a JS-level rejection that bubbles back as an
opaque `JS::Error` from `.await`.

Key pairs from asymmetric `generateKey` calls are returned as plain JS
dictionary objects, not arrays. The `{publicKey, privateKey}` destructuring
in MDN examples is ES2015 object shorthand for `{publicKey: publicKey,
privateKey: privateKey}` — analogous to Ruby 3.1+'s `{public_key:,
private_key:}` hash shorthand. Access is via property indexing
(`pair[:publicKey]`). The library distinguishes single keys from pairs by
checking `result[:constructor][:name].to_s == "CryptoKey"`.

## Cryptographic Choices

AES-GCM is the symmetric algorithm of choice. The library uses 12-byte IVs
by default. This is the recommended length per NIST SP 800-38D, and there
are concrete reasons not to deviate. AES-GCM's internals encrypt a sequence
of 128-bit counter blocks to produce the keystream. When the IV is exactly
12 bytes, GCM uses a fast path: it appends the 32-bit value `0x00000001` to
the IV and treats that as the initial counter block, incrementing the low
32 bits for each subsequent block. When the IV is any other length —
including 16 bytes — GCM instead runs the IV through GHASH (the same
universal hash used to compute the authentication tag) to derive the
initial counter block. This is both slower (an extra GHASH invocation per
encrypt/decrypt) and weaker (collision probability becomes roughly 2^64
rather than 2^96 for random IVs, because GHASH is a polynomial hash and not
a cryptographic hash). For applications needing more than 2^32 messages
under one key, the answer is not longer IVs but key rotation or AES-GCM-SIV.

For ECDSA, the default curve is P-256 with SHA-256 as the hash. Ed25519 is
a separate algorithm in WebCrypto's registry (not a curve choice for
ECDSA); it uses `{name: "Ed25519"}` with no hash parameter, because Ed25519
has a built-in hash. Browser support for Ed25519 in WebCrypto is solid in
recent Chrome/Safari/Firefox as of 2025 but was patchier before.

For hashing, SHA-256 is the workhorse. The library exposes `digest(data,
algorithm: "SHA-256")` returning bytes; SHA-384 and SHA-512 are equally
available via the same method, and SHA-1 is deliberately not exposed in the
default API even though WebCrypto supports it.

## Common Bugs and How to Avoid Them

Several bugs and almost-bugs surfaced during development. The patterns are
worth knowing.

The `ArrayBuffer` vs `Uint8Array` confusion appeared multiple times. Every
time a crypto operation returned an empty Ruby string, the cause was the
same: the result was an `ArrayBuffer`, the code tried to index it directly,
and `.length` returned `0` from `undefined`. The library now centralizes the
view-wrapping in `Util::JSArray.view`, which discriminates by
`constructor.name`. Any new method that returns a byte result should funnel
through `to_bytes`, which goes through `view`.

The IV-as-Ruby-String bug came from a helper named `JSArray.to_s` that
converted a `Uint8Array` to a Ruby byte string. A caller wrote `iv =
JSArray.to_s(getRandomValues(12))` and then passed `iv` to `encrypt`, where
WebCrypto rejected it because Ruby `String` becomes JS `String`, not
`BufferSource`. The library now uses `to_bytes` as the explicit name and
keeps the JS handle alive when callers will pass it back to another
WebCrypto operation. More importantly, the bytes-only public API now means
this conversion happens automatically inside the library; callers never see
the `Uint8Array` at all.

The `getRandomValues(length)` hardcoding bug was that an early version
ignored its `length` argument and always allocated 16 bytes. AES-GCM
accepted the resulting 16-byte IV because GCM accepts any IV length, so the
bug was invisible until performance work revealed that the slow GHASH path
was being taken. Tests for byte-producing helpers should explicitly assert
on output length.

`TextEncoder` for key material would silently corrupt any byte above 0x7F.
A 32-byte AES-256 key drawn from random bytes contains roughly 128 such
bytes; each one becomes two UTF-8 bytes after encoding, so the resulting
"key" arriving at `importKey` is much longer than 32 bytes and contains the
wrong bits. WebCrypto either rejects the wrong length or silently uses
something derived from the wrong material. The library never uses
`TextEncoder` for binary input; per-byte construction is the rule.

The `inspect` error on UUID-returning calls (and any other JS function
returning a primitive) doesn't break the value, only the display path.
`uuid = JS.global[:crypto].randomUUID.to_s` produces a clean Ruby `String`;
`p JS.global[:crypto].randomUUID` produces a confusing TypeError. Library
code that handles JS return values should immediately type-coerce.

A Hash-with-mixed-values options bag fails silently. `js_obj({name:
"AES-GCM", iv: js_uint8array})` works; passing the same hash directly to a
JS method does not, because the auto-conversion stumbles on the
non-primitive value. The library uses `Util.js_obj` universally to
eliminate this trap.

JS booleans compared truthily are always true. `if subtle.verify(...).await`
runs the if-branch even on a failed verification. The library always
converts: `== JS::True` returns a real Ruby boolean.

## Development Environment

The active development loop has two halves. Ruby code that doesn't touch
WebCrypto can be edited, tested, and benchmarked with native CRuby:
`bundle install`, `rspec`, RuboCop or Standard, the usual gem development
workflow. Ruby code that calls into WebCrypto needs a browser context
because `crypto.subtle` exists only there.

The browser-side workflow uses a small static HTML scratchpad that loads
`ruby.wasm` from a pinned CDN URL, then loads the library's `.rb` files via
fetch + `vm.eval`. A textarea + button + `<pre>` for output, with
`window.vm = vm` exposed so the DevTools console can drive `await
vm.evalAsync(\`...\`)` directly for interactive exploration. Serving via any
static HTTP server (`ruby -run -e httpd browser -p 8000` works fine);
WebCrypto requires a secure context, and `localhost` qualifies.

Pinning the ruby.wasm version (`@ruby/3.4-wasm-wasi@2.7.1` at time of
writing) matters because several quirks documented in this file are
version-dependent: the `JS::Object` inspect TypeError, the hash-with-mixed-
values auto-conversion behavior, the precise error messages for promise
rejections. Treating ruby.wasm upgrades as intentional events rather than
ambient drift makes regressions detectable.

VS Code with the Ruby LSP extension (`Shopify.ruby-lsp`) is the recommended
editor setup. The LSP handles the Ruby code analysis; the HTML/JS scratchpad
files are handled by VS Code natively. No ruby.wasm-specific extension is
needed.

For integration tests against real WebCrypto, the same scratchpad pattern is
used: a `tests.html` page loads the library and runs a test suite written
in Ruby that asserts and writes results to the DOM. This can be driven
headlessly via Playwright or Puppeteer for CI.

For pure-Ruby experimentation that doesn't need WebCrypto, `wasmtime
ruby.wasm` works locally — but `JS.global` doesn't exist in WASI mode the
way it does in browsers, so this is useful only for non-crypto, non-DOM
code paths.

## Open Questions and Future Work

Algorithm coverage is currently limited to AES-GCM, ECDSA, Ed25519, and
SHA-2 family hashes. Adding HMAC, RSA-PSS, RSA-OAEP, and AES-KW is
straightforward — each follows the same pattern of a capability check, a
parameter builder, a `subtle` call, and result byte extraction — but the
test surface grows linearly with each algorithm. Priority should follow
actual use cases as they emerge rather than chasing completeness.

PBKDF2, HKDF, and X25519 (key derivation) need a slightly different API
shape because the result is typically another `Key` rather than raw bytes.
The `derive_key` method on `WebCrypto::Key` should return a fresh
`WebCrypto::Key` with the derived key's properties; `derive_bits` returns
bytes directly. Both APIs should be exposed.

JWK import/export is needed for interop with most non-WebCrypto systems.
WebCrypto's `exportKey("jwk", key)` returns a JS dictionary object with the
JWK fields; the library will need to deeply convert this to a Ruby `Hash`
(recursively, since JWK includes nested arrays for key_ops). The reverse
(`importKey("jwk", ruby_hash, ...)`) needs to convert in the opposite
direction. This is the main place where the library will need a generic
"deep JS↔Ruby converter," distinct from the byte-string conversions used
elsewhere.

Signature wrapper types (`WebCrypto::Signature`, `WebCrypto::Ciphertext`)
were considered to disambiguate the byte-vs-byte semantic overload at
call sites like `verify(signature_bytes, data_bytes)`. Decision: not worth
it in the current scope. The Ruby community generally accepts byte strings
as polymorphic in this way, and documentation can clarify parameter
meaning.

The OpenSSL backend is the major next milestone. The shape should be
identical: `WebCrypto::Key#sign(bytes)` returns bytes whether the underlying
implementation is `subtle.sign` or `OpenSSL::PKey::EC#sign`. The selection
logic at load time picks the backend based on whether `JS.global` is
available. The Encoding module is fully backend-agnostic; the `Key` and
`KeyPair` classes hold an opaque internal reference (`@js` for WebCrypto,
`@pkey` for OpenSSL) and dispatch through the backend module. Tests should
run against both backends and produce identical byte outputs for the same
inputs — this is the main interop guarantee the library offers.

Naming of the library itself is worth revisiting. `WebCrypto` is descriptive
of the current backend but misleading once OpenSSL ships. Something like
`Cryptic`, `RbCrypto`, or even a domain-specific name (if the library has a
particular use case) might be better. Decision deferred until the backend
split lands; rename is mechanical at that point.
