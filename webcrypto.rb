require 'js'

module WebCrypto
  # Base class for every error this library raises, so callers can
  # `rescue WebCrypto::Error` broadly.
  class Error < StandardError; end

  # Raised when an operation is attempted that the key's usages do not permit.
  # Mirrors the InvalidAccessError WebCrypto itself would raise, but caught at
  # the Ruby boundary with a clearer message and before any JS call.
  class CapabilityError < Error; end

  module Util
    def self.js_obj(hash)
      obj = JS.global[:Object].new
      hash.each { |k, v| obj[k] = v }
      obj
    end

    module JSArray
      # Accept either a TypedArray or an ArrayBuffer
      def self.view(js_obj)
        name = js_obj[:constructor][:name].to_s
        name == "ArrayBuffer" ? JS.global[:Uint8Array].new(js_obj) : js_obj
      end

      def self.to_a(js_array)
        v = view(js_array)
        v[:length].to_i.times.map { |i| v[i].to_i }
      end

      def self.to_bytes(js_array)
        to_a(js_array).pack('C*')
      end

      # Build a Uint8Array from a Ruby byte String via per-byte construction.
      # Never goes through TextEncoder: every byte (including those above 0x7F)
      # crosses unchanged, so key material / ciphertext / IVs are preserved.
      def self.from_bytes(bytes)
        unless bytes.is_a?(String)
          raise TypeError, "expected a byte String, got #{bytes.class}"
        end

        arr = JS.global[:Uint8Array].new(bytes.bytesize)
        bytes.each_byte.with_index { |b, i| arr[i] = b }
        arr
      end
    end
  end

  # Hex and base64 helpers for moving byte Strings to/from text forms.
  #
  # Both directions use pack/unpack rather than the base64 gem (a bundled gem
  # since Ruby 3.4, not guaranteed present in the ruby.wasm build). "m0" is
  # strict base64 with no line wrapping, byte-identical to
  # Base64.strict_encode64 / strict_decode64 — the unwrapped form every modern
  # API and storage format expects.
  module Encoding
    def self.to_hex(bytes)
      bytes.unpack1("H*")
    end

    def self.from_hex(hex)
      [hex].pack("H*")
    end

    def self.to_base64(bytes)
      [bytes].pack("m0")
    end

    def self.from_base64(str)
      str.unpack1("m0")
    end
  end

  # Per-algorithm capability modules. All of an algorithm's modules are mixed
  # into a Key's singleton class, so the methods always exist for keys of that
  # algorithm; each method calls require_usage! first and raises CapabilityError
  # if the key's usages do not include the operation. Methods operate on the
  # wrapped JS CryptoKey through the Key's private @js handle.
  module Capabilities
    module AESGCM
      # NIST SP 800-38D recommended IV length. Exactly 12 bytes triggers GCM's
      # fast path (counter seeded from IV || 0x00000001); other lengths run the
      # IV through GHASH, which is slower and lowers the collision bound.
      IV_LENGTH = 12

      def self.validate_iv!(iv)
        raise TypeError, "iv must be a byte String, got #{iv.class}" unless iv.is_a?(String)
        return if iv.bytesize == IV_LENGTH

        raise ArgumentError, "AES-GCM iv must be #{IV_LENGTH} bytes, got #{iv.bytesize}"
      end

      module Encrypt
        def encrypt(plaintext, iv:)
          require_usage!("encrypt")
          AESGCM.validate_iv!(iv)
          data = WebCrypto::Util::JSArray.from_bytes(plaintext)
          iv_arr = WebCrypto::Util::JSArray.from_bytes(iv)
          result = JS.global[:crypto][:subtle]
                     .encrypt(WebCrypto::Util.js_obj(name: "AES-GCM", iv: iv_arr), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Decrypt
        def decrypt(ciphertext, iv:)
          require_usage!("decrypt")
          AESGCM.validate_iv!(iv)
          data = WebCrypto::Util::JSArray.from_bytes(ciphertext)
          iv_arr = WebCrypto::Util::JSArray.from_bytes(iv)
          result = JS.global[:crypto][:subtle]
                     .decrypt(WebCrypto::Util.js_obj(name: "AES-GCM", iv: iv_arr), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end
    end

    module AESCTR
      # The AES-CTR counter is a full AES block (16 bytes). `length` is how many
      # of its trailing bits form the incrementing counter; the leading bits are
      # the fixed nonce. 64 is the common split, giving 2^64 blocks per message.
      COUNTER_LENGTH = 16
      DEFAULT_LENGTH = 64

      def self.validate_counter!(counter)
        raise TypeError, "counter must be a byte String, got #{counter.class}" unless counter.is_a?(String)
        return if counter.bytesize == COUNTER_LENGTH

        raise ArgumentError, "AES-CTR counter must be #{COUNTER_LENGTH} bytes, got #{counter.bytesize}"
      end

      module Encrypt
        def encrypt(plaintext, counter:, length: DEFAULT_LENGTH)
          require_usage!("encrypt")
          AESCTR.validate_counter!(counter)
          data = WebCrypto::Util::JSArray.from_bytes(plaintext)
          counter_arr = WebCrypto::Util::JSArray.from_bytes(counter)
          result = JS.global[:crypto][:subtle]
                     .encrypt(WebCrypto::Util.js_obj(name: "AES-CTR", counter: counter_arr, length: length), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Decrypt
        def decrypt(ciphertext, counter:, length: DEFAULT_LENGTH)
          require_usage!("decrypt")
          AESCTR.validate_counter!(counter)
          data = WebCrypto::Util::JSArray.from_bytes(ciphertext)
          counter_arr = WebCrypto::Util::JSArray.from_bytes(counter)
          result = JS.global[:crypto][:subtle]
                     .decrypt(WebCrypto::Util.js_obj(name: "AES-CTR", counter: counter_arr, length: length), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end
    end

    module AESCBC
      # AES-CBC's IV is exactly one cipher block.
      IV_LENGTH = 16

      def self.validate_iv!(iv)
        raise TypeError, "iv must be a byte String, got #{iv.class}" unless iv.is_a?(String)
        return if iv.bytesize == IV_LENGTH

        raise ArgumentError, "AES-CBC iv must be #{IV_LENGTH} bytes, got #{iv.bytesize}"
      end

      module Encrypt
        def encrypt(plaintext, iv:)
          require_usage!("encrypt")
          AESCBC.validate_iv!(iv)
          data = WebCrypto::Util::JSArray.from_bytes(plaintext)
          iv_arr = WebCrypto::Util::JSArray.from_bytes(iv)
          result = JS.global[:crypto][:subtle]
                     .encrypt(WebCrypto::Util.js_obj(name: "AES-CBC", iv: iv_arr), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Decrypt
        def decrypt(ciphertext, iv:)
          require_usage!("decrypt")
          AESCBC.validate_iv!(iv)
          data = WebCrypto::Util::JSArray.from_bytes(ciphertext)
          iv_arr = WebCrypto::Util::JSArray.from_bytes(iv)
          result = JS.global[:crypto][:subtle]
                     .decrypt(WebCrypto::Util.js_obj(name: "AES-CBC", iv: iv_arr), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end
    end

    module AESKW
      # AES-KW (RFC 3394 key wrap) does not use encrypt/decrypt: it wraps and
      # unwraps CryptoKeys. There is no IV; the algorithm bag is just the name.
      # wrap_key takes another Key and returns the wrapped bytes; unwrap_key
      # takes wrapped bytes and returns a fresh Key.
      module WrapKey
        def wrap_key(key, format: "raw")
          require_usage!("wrapKey")
          result = JS.global[:crypto][:subtle]
                     .wrapKey(format, key.js, @js, WebCrypto::Util.js_obj(name: "AES-KW"))
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module UnwrapKey
        def unwrap_key(wrapped_key, algorithm:, usages:, extractable: true, format: "raw")
          require_usage!("unwrapKey")
          data = WebCrypto::Util::JSArray.from_bytes(wrapped_key)
          result = JS.global[:crypto][:subtle]
                     .unwrapKey(format, data, @js, WebCrypto::Util.js_obj(name: "AES-KW"),
                                WebCrypto::Util.js_obj(algorithm), extractable, usages)
                     .await
          WebCrypto::Key.new(result)
        end
      end
    end

    module ECDSA
      # The hash is not part of an ECDSA key (its algorithm only carries the
      # namedCurve); it is chosen per sign/verify call. When the caller does not
      # specify one, derive the conventional pairing from the key's curve
      # (RFC 7518 ES256/ES384/ES512), so a P-384 key signs with SHA-384 rather
      # than a hardcoded SHA-256. Callers may still override via `hash:`.
      #
      # namedCurve is a required member of EcKeyGenParams, so any working key has
      # one of these curves; an unrecognized curve means something unexpected and
      # is raised rather than silently defaulted.
      CURVE_HASH = {
        "P-256" => "SHA-256",
        "P-384" => "SHA-384",
        "P-521" => "SHA-512"
      }.freeze

      def self.default_hash(js_key)
        curve = js_key[:algorithm][:namedCurve].to_s
        CURVE_HASH[curve] || raise(ArgumentError, "unsupported ECDSA curve: #{curve.inspect}")
      end

      module Sign
        def sign(data, hash: nil)
          require_usage!("sign")
          hash ||= ECDSA.default_hash(@js)
          bytes = WebCrypto::Util::JSArray.from_bytes(data)
          result = JS.global[:crypto][:subtle]
                     .sign(WebCrypto::Util.js_obj(name: "ECDSA", hash: hash), @js, bytes)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Verify
        def verify(signature, data, hash: nil)
          require_usage!("verify")
          hash ||= ECDSA.default_hash(@js)
          sig_bytes = WebCrypto::Util::JSArray.from_bytes(signature)
          data_bytes = WebCrypto::Util::JSArray.from_bytes(data)
          JS.global[:crypto][:subtle]
            .verify(WebCrypto::Util.js_obj(name: "ECDSA", hash: hash), @js, sig_bytes, data_bytes)
            .await == JS::True
        end
      end
    end

    module Ed25519
      module Sign
        def sign(data)
          require_usage!("sign")
          bytes = WebCrypto::Util::JSArray.from_bytes(data)
          result = JS.global[:crypto][:subtle]
                     .sign(WebCrypto::Util.js_obj(name: "Ed25519"), @js, bytes)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Verify
        def verify(signature, data)
          require_usage!("verify")
          sig_bytes = WebCrypto::Util::JSArray.from_bytes(signature)
          data_bytes = WebCrypto::Util::JSArray.from_bytes(data)
          JS.global[:crypto][:subtle]
            .verify(WebCrypto::Util.js_obj(name: "Ed25519"), @js, sig_bytes, data_bytes)
            .await == JS::True
        end
      end
    end

    module RSASSA_PKCS1_v1_5
      # RSASSA-PKCS1-v1_5 binds its hash to the key at generation
      # (RsaHashedKeyGenParams), so sign/verify take no hash parameter and the
      # algorithm bag is just the name, like Ed25519. This is JWS RS256/384/512.
      module Sign
        def sign(data)
          require_usage!("sign")
          bytes = WebCrypto::Util::JSArray.from_bytes(data)
          result = JS.global[:crypto][:subtle]
                     .sign(WebCrypto::Util.js_obj(name: "RSASSA-PKCS1-v1_5"), @js, bytes)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Verify
        def verify(signature, data)
          require_usage!("verify")
          sig_bytes = WebCrypto::Util::JSArray.from_bytes(signature)
          data_bytes = WebCrypto::Util::JSArray.from_bytes(data)
          JS.global[:crypto][:subtle]
            .verify(WebCrypto::Util.js_obj(name: "RSASSA-PKCS1-v1_5"), @js, sig_bytes, data_bytes)
            .await == JS::True
        end
      end
    end

    module RSAPSS
      # RSA-PSS also binds its hash to the key (RsaHashedKeyGenParams), but the
      # signature additionally takes a per-call saltLength (in bytes). When
      # unspecified, default to the hash's digest length — the salt-equals-digest
      # convention of JWS PS256/384/512 (RFC 7518). Override via salt_length:.
      DIGEST_LENGTH = {
        "SHA-256" => 32,
        "SHA-384" => 48,
        "SHA-512" => 64
      }.freeze

      def self.default_salt_length(js_key)
        hash = js_key[:algorithm][:hash][:name].to_s
        DIGEST_LENGTH[hash] || raise(ArgumentError, "unsupported RSA-PSS hash: #{hash.inspect}")
      end

      module Sign
        def sign(data, salt_length: nil)
          require_usage!("sign")
          salt_length ||= RSAPSS.default_salt_length(@js)
          bytes = WebCrypto::Util::JSArray.from_bytes(data)
          result = JS.global[:crypto][:subtle]
                     .sign(WebCrypto::Util.js_obj(name: "RSA-PSS", saltLength: salt_length), @js, bytes)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Verify
        def verify(signature, data, salt_length: nil)
          require_usage!("verify")
          salt_length ||= RSAPSS.default_salt_length(@js)
          sig_bytes = WebCrypto::Util::JSArray.from_bytes(signature)
          data_bytes = WebCrypto::Util::JSArray.from_bytes(data)
          JS.global[:crypto][:subtle]
            .verify(WebCrypto::Util.js_obj(name: "RSA-PSS", saltLength: salt_length), @js, sig_bytes, data_bytes)
            .await == JS::True
        end
      end
    end

    module RSAOAEP
      # RSA-OAEP is RSA encryption (encrypt/decrypt). Its hash is bound to the
      # key at generation (RsaHashedKeyGenParams); the only per-call parameter is
      # an optional label (associated data), which encrypt and decrypt must agree
      # on. Omitted by default.
      def self.algorithm(label)
        bag = { name: "RSA-OAEP" }
        bag[:label] = WebCrypto::Util::JSArray.from_bytes(label) unless label.nil?
        WebCrypto::Util.js_obj(bag)
      end

      module Encrypt
        def encrypt(plaintext, label: nil)
          require_usage!("encrypt")
          data = WebCrypto::Util::JSArray.from_bytes(plaintext)
          result = JS.global[:crypto][:subtle]
                     .encrypt(RSAOAEP.algorithm(label), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Decrypt
        def decrypt(ciphertext, label: nil)
          require_usage!("decrypt")
          data = WebCrypto::Util::JSArray.from_bytes(ciphertext)
          result = JS.global[:crypto][:subtle]
                     .decrypt(RSAOAEP.algorithm(label), @js, data)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end
    end

    module HMAC
      # HMAC is a symmetric MAC: one key carries both sign and verify, and its
      # hash is bound at generation (HmacKeyGenParams), so the per-call bag is
      # just the name, like Ed25519. verify delegates to subtle.verify, which
      # compares the MAC in constant time — never compare MACs in Ruby.
      module Sign
        def sign(data)
          require_usage!("sign")
          bytes = WebCrypto::Util::JSArray.from_bytes(data)
          result = JS.global[:crypto][:subtle]
                     .sign(WebCrypto::Util.js_obj(name: "HMAC"), @js, bytes)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module Verify
        def verify(signature, data)
          require_usage!("verify")
          sig_bytes = WebCrypto::Util::JSArray.from_bytes(signature)
          data_bytes = WebCrypto::Util::JSArray.from_bytes(data)
          JS.global[:crypto][:subtle]
            .verify(WebCrypto::Util.js_obj(name: "HMAC"), @js, sig_bytes, data_bytes)
            .await == JS::True
        end
      end
    end

    module PBKDF2
      # Password-based key derivation. The base key is imported from password
      # bytes (see WebCrypto.import_key); the per-call params are salt,
      # iterations, and hash. derive_bits returns raw bytes; derive_key returns a
      # fresh Key described by derived_key_algorithm.
      def self.algorithm(salt:, iterations:, hash:)
        WebCrypto::Util.js_obj(
          name: "PBKDF2",
          salt: WebCrypto::Util::JSArray.from_bytes(salt),
          iterations: iterations,
          hash: hash
        )
      end

      module DeriveBits
        def derive_bits(length:, salt:, iterations:, hash: "SHA-256")
          require_usage!("deriveBits")
          result = JS.global[:crypto][:subtle]
                     .deriveBits(PBKDF2.algorithm(salt: salt, iterations: iterations, hash: hash), @js, length)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module DeriveKey
        def derive_key(derived_key_algorithm:, usages:, salt:, iterations:, hash: "SHA-256", extractable: true)
          require_usage!("deriveKey")
          result = JS.global[:crypto][:subtle]
                     .deriveKey(PBKDF2.algorithm(salt: salt, iterations: iterations, hash: hash), @js,
                                WebCrypto::Util.js_obj(derived_key_algorithm), extractable, usages)
                     .await
          WebCrypto::Key.new(result)
        end
      end
    end

    module HKDF
      # HMAC-based extract-and-expand key derivation. The base key is imported
      # from secret bytes; the per-call params are salt, info, and hash. Unlike
      # PBKDF2 there is no iteration count (HKDF is not a password stretcher).
      def self.algorithm(salt:, info:, hash:)
        WebCrypto::Util.js_obj(
          name: "HKDF",
          salt: WebCrypto::Util::JSArray.from_bytes(salt),
          info: WebCrypto::Util::JSArray.from_bytes(info),
          hash: hash
        )
      end

      module DeriveBits
        def derive_bits(length:, salt:, info:, hash: "SHA-256")
          require_usage!("deriveBits")
          result = JS.global[:crypto][:subtle]
                     .deriveBits(HKDF.algorithm(salt: salt, info: info, hash: hash), @js, length)
                     .await
          WebCrypto::Util::JSArray.to_bytes(result)
        end
      end

      module DeriveKey
        def derive_key(derived_key_algorithm:, usages:, salt:, info:, hash: "SHA-256", extractable: true)
          require_usage!("deriveKey")
          result = JS.global[:crypto][:subtle]
                     .deriveKey(HKDF.algorithm(salt: salt, info: info, hash: hash), @js,
                                WebCrypto::Util.js_obj(derived_key_algorithm), extractable, usages)
                     .await
          WebCrypto::Key.new(result)
        end
      end
    end

    CAPABILITY_MAP = {
      "AES-GCM" => { "encrypt" => AESGCM::Encrypt, "decrypt" => AESGCM::Decrypt },
      "AES-CTR" => { "encrypt" => AESCTR::Encrypt, "decrypt" => AESCTR::Decrypt },
      "AES-CBC" => { "encrypt" => AESCBC::Encrypt, "decrypt" => AESCBC::Decrypt },
      "AES-KW"  => { "wrapKey" => AESKW::WrapKey,  "unwrapKey" => AESKW::UnwrapKey },
      "ECDSA"   => { "sign"    => ECDSA::Sign,     "verify"  => ECDSA::Verify   },
      "Ed25519" => { "sign"    => Ed25519::Sign,   "verify"  => Ed25519::Verify },
      "RSASSA-PKCS1-v1_5" => { "sign" => RSASSA_PKCS1_v1_5::Sign, "verify" => RSASSA_PKCS1_v1_5::Verify },
      "RSA-PSS" => { "sign" => RSAPSS::Sign, "verify" => RSAPSS::Verify },
      "RSA-OAEP" => { "encrypt" => RSAOAEP::Encrypt, "decrypt" => RSAOAEP::Decrypt },
      "HMAC" => { "sign" => HMAC::Sign, "verify" => HMAC::Verify },
      "PBKDF2" => { "deriveBits" => PBKDF2::DeriveBits, "deriveKey" => PBKDF2::DeriveKey },
      "HKDF" => { "deriveBits" => HKDF::DeriveBits, "deriveKey" => HKDF::DeriveKey }
      # extend as needed
    }.freeze
  end

  # A WebCrypto CryptoKey with a Ruby-native surface. The JS handle is held in a
  # private @js and never exposed to callers; capability methods (encrypt, sign,
  # ...) are mixed into the instance's singleton class for the key's algorithm,
  # and each checks the key's usages at call time (see require_usage!).
  class Key
    def initialize(js)
      @js = js
      # A CryptoKey's usages are immutable, so snapshot them once. Frozen so a
      # caller can't mutate the array and skew later require_usage! checks.
      @usages = read_usages.freeze
      install_capabilities
    end

    def algorithm_name
      @js[:algorithm][:name].to_s
    end

    attr_reader :usages

    protected

    # Exposed only to other Keys (AES-KW wrap_key needs the JS handle of the key
    # being wrapped). Protected keeps it off the public surface.
    attr_reader :js

    private

    def read_usages
      u = @js[:usages]
      u[:length].to_i.times.map { |i| u[i].to_s }
    end

    def install_capabilities
      sclass = (class << self; self; end)
      mods = Capabilities::CAPABILITY_MAP[algorithm_name] || {}
      mods.each_value { |mod| sclass.include(mod) }
    end

    # Capability enforcement at the Ruby boundary, mirroring WebCrypto's own
    # usage checks. Raises before any JS call so misuse surfaces early.
    def require_usage!(usage)
      return if usages.include?(usage)

      raise CapabilityError,
            "key does not permit #{usage} (usages: #{usages.join(', ')})"
    end
  end

  KeyPair = Struct.new(:public_key, :private_key)

  def self.generate_key(algorithm, extractable, usages)
    result = JS.global[:crypto][:subtle]
               .generateKey(WebCrypto::Util.js_obj(algorithm), extractable, usages)
               .await

    if result[:constructor][:name].to_s == "CryptoKey"
      Key.new(result)
    else
      KeyPair.new(Key.new(result[:publicKey]), Key.new(result[:privateKey]))
    end
  end

  # Import keying material as a Key. Needed for algorithms that cannot be
  # generated (PBKDF2/HKDF base keys come from raw password/secret bytes), and
  # generally for loading externally-produced keys. key_data is Ruby bytes for
  # the byte formats ("raw"/"spki"/"pkcs8"); "jwk" import is deferred to the JWK
  # work, which needs a deep Ruby->JS converter.
  def self.import_key(format, key_data, algorithm, extractable, usages)
    if format == "jwk"
      raise ArgumentError, "JWK import is not supported yet; use a byte format (raw/spki/pkcs8)"
    end

    data = WebCrypto::Util::JSArray.from_bytes(key_data)
    result = JS.global[:crypto][:subtle]
               .importKey(format, data, WebCrypto::Util.js_obj(algorithm), extractable, usages)
               .await
    Key.new(result)
  end

  # Supported message digests. SHA-1 is intentionally omitted: WebCrypto
  # supports it, but it is not collision-resistant, so the library does not
  # surface it in the default API.
  DIGEST_ALGORITHMS = ["SHA-256", "SHA-384", "SHA-512"].freeze

  # Hash bytes with crypto.subtle.digest. Keyless, so it lives on the top-level
  # module rather than on Key. Takes Ruby bytes and returns Ruby bytes.
  def self.digest(data, algorithm: "SHA-256")
    unless DIGEST_ALGORITHMS.include?(algorithm)
      raise ArgumentError,
            "unsupported digest algorithm: #{algorithm.inspect} " \
            "(expected one of #{DIGEST_ALGORITHMS.join(', ')})"
    end

    bytes = WebCrypto::Util::JSArray.from_bytes(data)
    result = JS.global[:crypto][:subtle].digest(algorithm, bytes).await
    WebCrypto::Util::JSArray.to_bytes(result)
  end

  def self.getRandomValues(length)
    buf = JS.global[:Uint8Array].new(length)
    JS.global[:crypto].getRandomValues(buf)
    buf
  end

  # Only available under Secure Context
  def self.randomUUID()
    JS.global[:crypto].randomUUID().to_s
  end
end
