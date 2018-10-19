module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      class OpenKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey           :hkey
        rrp_unicode_string :lp_sub_key
        string             :pad, length: -> { pad_length }
        uint32             :dw_options
        regsam             :sam_desired

        def initialize_instance
          super
          @opnum = REG_OPEN_KEY
        end

        # Determines the correct length for the padding in front of
        # #dw_options. It should always force a 4-byte alignment.
        def pad_length
          offset = (lp_sub_key.abs_offset + lp_sub_key.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end

