module RubySMB
  module Dcerpc
    module Winreg

      class RpcHkey < Ndr::NdrContextHandle; end

      class CloseKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        rpc_hkey  :hkey

        def initialize_instance
          super
          @opnum = REG_CLOSE_KEY
        end
      end

    end
  end
end


