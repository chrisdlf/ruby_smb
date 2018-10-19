module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      class QueryInfoKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey           :hkey
        rrp_unicode_string :lp_class, initial_value: 0

        def initialize_instance
          super
          @opnum = REG_QUERY_INFO_KEY
        end
      end

    end
  end
end


