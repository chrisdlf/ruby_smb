module RubySMB
  module Dcerpc
    module Winreg

      class PrpcHkey < Ndr::NdrContextHandle; end

      class OpenKeyResponse < BinData::Record
        attr_reader :opnum

        endian    :little
        prpc_hkey :phk_result
        uint32    :error_status

        def initialize_instance
          super
          @opnum = REG_OPEN_KEY
        end
      end

    end
  end
end

