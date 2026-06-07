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

# --- Ed25519 (may be unsupported on older browsers) ---------------------------
Tests.test("Ed25519 sign/verify round-trips") do
  pair = WebCrypto.generate_key({ name: "Ed25519" }, true, ["sign", "verify"])
  msg = "edwards".b
  sig = pair.private_key.sign(msg)
  Tests.assert(pair.public_key.verify(sig, msg), "valid signature should verify")
end

Tests.results.to_json
