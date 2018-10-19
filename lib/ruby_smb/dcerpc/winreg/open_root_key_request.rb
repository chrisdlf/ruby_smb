module RubySMB
  module Dcerpc
    module Winreg

      class PRegistryServerName < BinData::Record
        endian :little

        uint32   :referent_id
        string16 :server_name, read_length: -> { 4 }
      end

      class OpenRootKeyRequest < BinData::Record
        attr_reader :opnum

        endian :little

        p_registry_server_name :p_registry_server_name
        regsam                 :regsam

        def initialize_instance
          super
          @opnum = get_parameter(:opnum) if has_parameter?(:opnum)
          p_registry_server_name.referent_id = 0x00020000
          p_registry_server_name.server_name = "\0\0".encode('utf-16le')
          regsam.maximum = 1 unless @opnum == OPEN_HKPD
        end
      end

    end
  end
end
