# Browser test suite for webcrypto-rb. Loaded by tests.html via fetch + eval
# and run inside vm.evalAsync, so the WebCrypto `.await` calls work. The suite
# accumulates results and the final expression returns them as JSON; tests.html
# renders them to the DOM (and exposes them for headless drivers).
require "json"

module Tests
  @results = []

  class << self
    attr_reader :results

    def test(name)
      yield
      @results << { name: name, ok: true, message: "" }
    rescue StandardError => e
      @results << { name: name, ok: false, message: "#{e.class}: #{e.message}" }
    end

    def assert(cond, message = "assertion failed")
      raise message unless cond
    end

    def assert_equal(expected, actual)
      return if expected == actual

      raise "expected #{expected.inspect}, got #{actual.inspect}"
    end

    def assert_raises(klass)
      yield
      raise "expected #{klass} to be raised, but nothing was"
    rescue StandardError => e
      raise "expected #{klass}, got #{e.class}: #{e.message}" unless e.is_a?(klass)
    end

    def random_iv(length = 12)
      WebCrypto::Util::JSArray.to_bytes(WebCrypto.getRandomValues(length))
    end
  end
end

# --- Encoding (pure Ruby, no WebCrypto) ---------------------------------------
Tests.test("Encoding hex round-trips all byte values") do
  bytes = (0..255).to_a.pack("C*")
  Tests.assert_equal(bytes, WebCrypto::Encoding.from_hex(WebCrypto::Encoding.to_hex(bytes)))
end

Tests.test("Encoding base64 is strict and unwrapped") do
  b64 = WebCrypto::Encoding.to_base64("hello world".b)
  Tests.assert(!b64.include?("\n"), "base64 should not contain newlines")
  Tests.assert_equal("hello world".b, WebCrypto::Encoding.from_base64(b64))
end

# --- digest (known-answer, no randomness) -------------------------------------
Tests.test("digest SHA-256 of 'abc' matches the known answer") do
  digest = WebCrypto.digest("abc".b, algorithm: "SHA-256")
  Tests.assert_equal(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    WebCrypto::Encoding.to_hex(digest)
  )
end

Tests.test("digest rejects SHA-1") do
  Tests.assert_raises(ArgumentError) { WebCrypto.digest("abc".b, algorithm: "SHA-1") }
end

# --- AES-GCM ------------------------------------------------------------------
Tests.test("AES-GCM encrypt/decrypt round-trips") do
  key = WebCrypto.generate_key({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
  iv = Tests.random_iv
  msg = "attack at dawn".b
  ct = key.encrypt(msg, iv: iv)
  Tests.assert_equal(msg, key.decrypt(ct, iv: iv))
end

Tests.test("AES-GCM rejects a wrong-length IV") do
  key = WebCrypto.generate_key({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"])
  Tests.assert_raises(ArgumentError) { key.encrypt("x".b, iv: "short".b) }
end

# --- capability enforcement ---------------------------------------------------
Tests.test("an encrypt-only key raises CapabilityError on decrypt") do
  key = WebCrypto.generate_key({ name: "AES-GCM", length: 256 }, true, ["encrypt"])
  iv = Tests.random_iv
  ct = key.encrypt("x".b, iv: iv)
  Tests.assert_raises(WebCrypto::CapabilityError) { key.decrypt(ct, iv: iv) }
end

# --- ECDSA --------------------------------------------------------------------
Tests.test("ECDSA P-256 sign/verify round-trips and detects tampering") do
  pair = WebCrypto.generate_key({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])
  msg = "sign me".b
  sig = pair.private_key.sign(msg)
  Tests.assert(pair.public_key.verify(sig, msg), "valid signature should verify")
  Tests.assert(!pair.public_key.verify(sig, "tampered".b), "tampered message should not verify")
end

# --- HMAC ---------------------------------------------------------------------
Tests.test("HMAC SHA-256 sign/verify round-trips and detects tampering") do
  key = WebCrypto.generate_key({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"])
  msg = "mac me".b
  mac = key.sign(msg)
  Tests.assert(key.verify(mac, msg), "valid MAC should verify")
  Tests.assert(!key.verify(mac, "tampered".b), "tampered message should not verify")
end

# --- RSA-OAEP -----------------------------------------------------------------
Tests.test("RSA-OAEP encrypt/decrypt round-trips (with and without label)") do
  pubexp = WebCrypto::Util::JSArray.from_bytes("\x01\x00\x01".b)
  pair = WebCrypto.generate_key(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: pubexp, hash: "SHA-256" },
    true, ["encrypt", "decrypt"]
  )
  msg = "secret".b
  ct = pair.public_key.encrypt(msg)
  Tests.assert_equal(msg, pair.private_key.decrypt(ct))

  label = "context".b
  ct2 = pair.public_key.encrypt(msg, label: label)
  Tests.assert_equal(msg, pair.private_key.decrypt(ct2, label: label))
end

# --- PBKDF2 -------------------------------------------------------------------
Tests.test("PBKDF2 derive_bits returns the requested length and is deterministic") do
  base = WebCrypto.import_key("raw", "password".b, { name: "PBKDF2" }, false, ["deriveBits"])
  salt = "salt-salt".b
  bits1 = base.derive_bits(length: 256, salt: salt, iterations: 1000, hash: "SHA-256")
  bits2 = base.derive_bits(length: 256, salt: salt, iterations: 1000, hash: "SHA-256")
  Tests.assert_equal(32, bits1.bytesize)
  Tests.assert_equal(bits1, bits2)
end

Tests.test("PBKDF2 derive_key produces a usable AES-GCM key") do
  base = WebCrypto.import_key("raw", "password".b, { name: "PBKDF2" }, false, ["deriveKey"])
  key = base.derive_key(
    derived_key_algorithm: { name: "AES-GCM", length: 256 },
    usages: ["encrypt", "decrypt"],
    salt: "salt-salt".b, iterations: 1000, hash: "SHA-256"
  )
  iv = Tests.random_iv
  ct = key.encrypt("derived".b, iv: iv)
  Tests.assert_equal("derived".b, key.decrypt(ct, iv: iv))
end

# --- HKDF ---------------------------------------------------------------------
Tests.test("HKDF derive_bits returns the requested length and is deterministic") do
  base = WebCrypto.import_key("raw", ("k" * 16).b, { name: "HKDF" }, false, ["deriveBits"])
  bits1 = base.derive_bits(length: 256, salt: "salt".b, info: "app-info".b, hash: "SHA-256")
  bits2 = base.derive_bits(length: 256, salt: "salt".b, info: "app-info".b, hash: "SHA-256")
  Tests.assert_equal(32, bits1.bytesize)
  Tests.assert_equal(bits1, bits2)
end

# --- ECDH ---------------------------------------------------------------------
Tests.test("ECDH P-256 derive_bits agrees between two parties") do
  alice = WebCrypto.generate_key({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
  bob   = WebCrypto.generate_key({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"])
  a = alice.private_key.derive_bits(bob.public_key, length: 256)
  b = bob.private_key.derive_bits(alice.public_key, length: 256)
  Tests.assert_equal(32, a.bytesize)
  Tests.assert_equal(a, b)
end

# --- X25519 (may be unsupported on older browsers) ----------------------------
Tests.test("X25519 derive_bits agrees between two parties") do
  alice = WebCrypto.generate_key({ name: "X25519" }, true, ["deriveBits"])
  bob   = WebCrypto.generate_key({ name: "X25519" }, true, ["deriveBits"])
  a = alice.private_key.derive_bits(bob.public_key, length: 256)
  b = bob.private_key.derive_bits(alice.public_key, length: 256)
  Tests.assert_equal(32, a.bytesize)
  Tests.assert_equal(a, b)
end

# --- Ed25519 (may be unsupported on older browsers) ---------------------------
Tests.test("Ed25519 sign/verify round-trips") do
  pair = WebCrypto.generate_key({ name: "Ed25519" }, true, ["sign", "verify"])
  msg = "edwards".b
  sig = pair.private_key.sign(msg)
  Tests.assert(pair.public_key.verify(sig, msg), "valid signature should verify")
end

Tests.results.to_json
