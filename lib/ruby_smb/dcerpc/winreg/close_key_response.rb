module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      class CloseKeyResponse < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey  :hkey
        uint32    :error_status

        def initialize_instance
          super
          @opnum = REG_CLOSE_KEY
        end
      end

    end
  end
end


