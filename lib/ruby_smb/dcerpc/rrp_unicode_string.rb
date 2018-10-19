module RubySMB
  module Dcerpc

    class RrpUnicodeString < BinData::Primitive
      endian :little

      uint16     :buffer_length,  initial_value: -> { buffer.to_s == "\0" ? 0 : buffer.actual_count * 2 }
      uint16     :maximum_length, initial_value: -> { buffer.to_s == "\0" ? 0 : buffer.max_count * 2 }
      ndr_lp_str :buffer

      def get
        self.buffer
      end

      def set(buf)
        self.buffer = buf
        self.buffer_length = self.buffer.to_s == "\0" ? 0 : self.buffer.actual_count * 2
        self.maximum_length = self.buffer.to_s == "\0" ? 0 : self.buffer.max_count * 2
      end
    end

    class PrrpUnicodeString < BinData::Primitive
      endian :little

      uint32 :referent_identifier, initial_value: 0x00020000
      rrp_unicode_string :rrp_unicode_string

      def get
        self.rrp_unicode_string
      end

      def set(buf)
        self.rrp_unicode_string = buf
      end
    end

  end
end

