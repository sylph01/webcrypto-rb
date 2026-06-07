require 'js'

module WebCrypto
  module Util
    module JSArray
      def self.to_a(js_array)
        js_array[:length].to_i.times.map { |i| js_array[i].to_i }
      end

      def self.to_hex_a(js_array)
        js_array[:length].to_i.times.map { |i| js_array[i].to_i.to_s(16).rjust(2, '0') }
      end

      def self.to_s(js_array)
        self.to_a(js_array).pack('C*')
      end
    end
  end

  def self.getRandomValues(length)
    buf = JS.global[:Uint8Array].new(16)
    JS.global[:crypto].getRandomValues(buf)
    buf
  end

  def self.randomUUID()
    JS.global[:crypto].randomUUID().to_s
  end
end