require 'openssl'
require 'base64'

module MoneyTree
  module Support
    include OpenSSL

    INT32_MAX = 256 ** [1].pack("L*").size
    INT64_MAX = 256 ** [1].pack("Q*").size
    BASE58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def int_to_base58(int_val, leading_zero_bytes=0)
      base58_val, base = '', BASE58_CHARS.size
      while int_val > 0
        int_val, remainder = int_val.divmod(base)
        base58_val = BASE58_CHARS[remainder] + base58_val
      end
      base58_val
    end

    def base58_to_int(base58_val)
      int_val, base = 0, BASE58_CHARS.size
      base58_val.reverse.each_char.with_index do |char,index|
        raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = BASE58_CHARS.index(char)
        int_val += char_index*(base**index)
      end
      int_val
    end

    def encode_base58(hex)
      leading_zero_bytes  = (hex.match(/^([0]+)/) ? $1 : '').size / 2
      ("1"*leading_zero_bytes) + int_to_base58( hex.to_i(16) )
    end

    def decode_base58(base58_val)
      s = base58_to_int(base58_val).to_s(16); s = (s.bytesize.odd? ? '0'+s : s)
      s = '' if s == '00'
      leading_zero_bytes = (base58_val.match(/^([1]+)/) ? $1 : '').size
      s = ("00"*leading_zero_bytes) + s  if leading_zero_bytes > 0
      s
    end
    alias_method :base58_to_hex, :decode_base58

    def to_serialized_base58(hex)
      hash = sha256 hex
      hash = sha256 hash
      checksum = hash.slice(0..7)
      address = hex + checksum
      encode_base58 address
    end

    def to_serialized_bech32(witness_program_hex, version: 0, hrp: 'bc')
      witness_program = [witness_program_hex].pack("H*")

      return nil if version > 16
      length = witness_program.size
      return nil if version == 0 && length != 20 && length != 32
      return nil if length < 2 || length > 40

      data = [ version ] + convert_bits(witness_program.unpack("C*"), from_bits: 8, to_bits: 5, pad: true)
      address = MoneyTree::Bech32.encode(hrp, data)

      return address.nil? ? nil : address
    end

    def from_serialized_base58(base58)
      hex = decode_base58 base58
      checksum = hex.slice!(-8..-1)
      compare_checksum = sha256(sha256(hex)).slice(0..7)
      raise EncodingError unless checksum == compare_checksum
      hex
    end

    def digestify(digest_type, source, opts = {})
      source = [source].pack("H*") unless opts[:ascii]
      bytes_to_hex Digest.digest(digest_type, source)
    end

    def sha256(source, opts = {})
      digestify('SHA256', source, opts)
    end

    def ripemd160(source, opts = {})
      digestify('RIPEMD160', source, opts)
    end

    def hash160(hex)
      ripemd160(sha256(hex))
    end

    def encode_base64(hex)
      Base64.encode64([hex].pack("H*")).chomp
    end

    def decode_base64(base64)
      Base64.decode64(base64).unpack("H*")[0]
    end

    def hmac_sha512(key, message)
      digest = Digest::SHA512.new
      HMAC.digest digest, key, message
    end

    def hmac_sha512_hex(key, message)
      md = hmac_sha512(key, message)
      md.unpack("H*").first.rjust(64, '0')
    end

    def bytes_to_int(bytes, base = 16)
      if bytes.is_a?(Array)
        bytes = bytes.pack("C*")
      end
      bytes.unpack("H*")[0].to_i(16)
    end

    def int_to_hex(i, size=nil)
      hex = i.to_s(16).downcase
      if (hex.size % 2) != 0
        hex = "#{0}#{hex}"
      end

      if size
        hex.rjust(size, "0")
      else
        hex
      end
    end

    def int_to_bytes(i)
      [int_to_hex(i)].pack("H*")
    end

    def bytes_to_hex(bytes)
      bytes.unpack("H*")[0].downcase
    end

    def hex_to_bytes(hex)
      [hex].pack("H*")
    end

    def hex_to_int(hex)
      hex.to_i(16)
    end

    def convert_bits(chunks, from_bits:, to_bits:, pad:)
      output_mask = (1 << to_bits) - 1
      buffer_mask = (1 << (from_bits + to_bits - 1)) - 1

      buffer = 0
      bits = 0

      output = []
      chunks.each do |chunk|
        buffer = ((buffer << from_bits) | chunk) & buffer_mask
        bits += from_bits
        while bits >= to_bits
          bits -= to_bits
          output << ((buffer >> bits) & output_mask)
        end
      end

      output << ((buffer << (to_bits - bits)) & output_mask) if pad && bits > 0

      if !pad && (bits >= from_bits || ((buffer << (to_bits - bits)) & output_mask) != 0)
        return nil
      end

      output
    end
  end
end
