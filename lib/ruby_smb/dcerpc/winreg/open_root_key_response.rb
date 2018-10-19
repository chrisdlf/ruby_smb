module RubySMB
  module Dcerpc
    module Winreg

      class PrpcHkey < Ndr::NdrContextHandle; end

      class OpenRootKeyResponse < BinData::Record
        attr_reader :opnum

        endian    :little
        prpc_hkey :ph_key
        uint32    :error_status

        def initialize_instance
          super
          @opnum = get_parameter(:root_key) if has_parameter?(:root_key)
        end
      end

    end
  end
end
