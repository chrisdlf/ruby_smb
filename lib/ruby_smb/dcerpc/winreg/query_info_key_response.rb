module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      class QueryInfoKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rrp_unicode_string :lp_class, initial_value: 0
        string             :pad,      length: -> { pad_length }
        uint32             :lpc_sub_keys
        uint32             :lpc_max_sub_key_len
        uint32             :lpc_max_class_len
        uint32             :lpc_values
        uint32             :lpcb_max_value_name_len
        uint32             :lpcb_max_value_len
        uint32             :lpcb_security_descriptor
        file_time          :lpft_last_write_time
        uint32             :error_status

        def initialize_instance
          super
          @opnum = REG_QUERY_INFO_KEY
        end

        # Determines the correct length for the padding in front of
        # #lpc_sub_keys. It should always force a 4-byte alignment.
        def pad_length
          offset = (lp_class.abs_offset + lp_class.to_binary_s.length) % 4
          (4 - offset) % 4
        end
      end

    end
  end
end


