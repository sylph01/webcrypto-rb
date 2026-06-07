require 'js'

module WebCrypto
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

      def self.to_hex_array(js_array)
        to_a(js_array).map { |b| b.to_s(16).rjust(2, '0') }
      end

      def self.to_bytes(js_array)
        to_a(js_array).pack('C*')
      end
    end
  end

  module CryptoKey
    KeyPair = Struct.new(:public_key, :private_key)

    module Base
      def algorithm_name
        self[:algorithm][:name].to_s
      end

      def usages
        u = self[:usages]
        u[:length].to_i.times.map { |i| u[i].to_s }
      end
    end

    module AESGCM
      module Encrypt
        def encrypt(plaintext, iv:)
          encoded = plaintext.is_a?(String) ? JS.global[:TextEncoder].new.encode(plaintext) : plaintext
          JS.global[:crypto][:subtle]
            .encrypt(WebCrypto::Util.js_obj(name: "AES-GCM", iv: iv), self, encoded)
            .await
        end
      end

      module Decrypt
        def decrypt(ciphertext, iv:)
          JS.global[:crypto][:subtle]
            .decrypt(WebCrypto::Util.js_obj(name: "AES-GCM", iv: iv), self, ciphertext)
            .await
        end
      end
    end

    module ECDSA
      module Sign
        def sign(data, hash: "SHA-256")
          JS.global[:crypto][:subtle]
            .sign(WebCrypto::Util.js_obj(name: "ECDSA", hash: hash), self, data)
            .await
        end
      end

      module Verify
        def verify(signature, data, hash: "SHA-256")
          JS.global[:crypto][:subtle]
            .verify(WebCrypto::Util.js_obj(name: "ECDSA", hash: hash), self, signature, data)
            .await == JS::True
        end
      end
    end

    module Ed25519
      module Sign
        def sign(data)
          JS.global[:crypto][:subtle]
            .sign(WebCrypto::Util.js_obj(name: "Ed25519"), self, data)
            .await
        end
      end

      module Verify
        def verify(signature, data)
          JS.global[:crypto][:subtle]
            .verify(WebCrypto::Util.js_obj(name: "Ed25519"), self, signature, data)
            .await == JS::True
        end
      end
    end

    CAPABILITY_MAP = {
      "AES-GCM" => { "encrypt" => AESGCM::Encrypt, "decrypt" => AESGCM::Decrypt },
      "ECDSA"   => { "sign"    => ECDSA::Sign,     "verify"  => ECDSA::Verify   },
      "Ed25519" => { "sign"    => Ed25519::Sign,   "verify"  => Ed25519::Verify }
      # extend as needed
    }.freeze

    def self.wrap(key)
      sclass = (class << key; self; end)
      sclass.include(Base)
      mods = CAPABILITY_MAP[key.algorithm_name] || {}
      key.usages.each do |u|
        sclass.include(mods[u]) if mods[u]
      end
      key
    end

    def self.generate_key(algorithm, is_extractable, key_usages)
      result = JS.global[:crypto][:subtle]
                 .generateKey(WebCrypto::Util.js_obj(algorithm), is_extractable, key_usages)
                 .await

      if result[:constructor][:name].to_s == "CryptoKey"
        wrap(result)
      else
        KeyPair.new(wrap(result[:publicKey]), wrap(result[:privateKey]))
      end
    end
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
