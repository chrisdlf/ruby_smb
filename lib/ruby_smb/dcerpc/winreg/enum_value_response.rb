module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      class EnumValueResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rrp_unicode_string :lp_value_name
        string             :pad, length: -> { pad_length }
        ndr_lp_dword       :lp_type
        ndr_lp_byte        :lp_data
        ndr_lp_dword       :lpcb_data
        ndr_lp_dword       :lpcb_len
        uint32             :error_status

        def initialize_instance
          super
          @opnum = REG_ENUM_VALUE
        end

        # Determines the correct length for the padding in front of
        # #lp_type. It should always force a 4-byte alignment.
        def pad_length
          offset = (lp_value_name.abs_offset + lp_value_name.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end

