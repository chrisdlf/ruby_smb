module RubySMB
  module SMB1
    module Packet

      # A SMB1 SMB_COM_READ_ANDX Response Packet as defined in
      # [2.2.4.42.2 Response](https://msdn.microsoft.com/en-us/library/ee441872.aspx)
      # [2.2.4.2.2 Server Response Extensions](https://msdn.microsoft.com/en-us/library/ff470017.aspx)
      class ReadAndxResponse < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {ReadAndxResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian  :little
          uint8   :andx_command,         label: 'AndX Command',         initial_value: 0xFF
          uint8   :andx_reserved,        label: 'AndX Reserved',        initial_value: 0x00
          uint16  :andx_offset,          label: 'AndX Offset'
          uint16  :available,            label: 'Available'
          uint16  :data_compaction_mode, label: 'Data Compaction Mode', initial_value: 0x0000
          uint16  :reserved,             label: 'Reserved',             initial_value: 0x0000
          uint16  :data_length,          label: 'Data Length'
          uint16  :data_offset,          label: 'Data Offset'
          uint16  :data_length_high,     label: 'Data Length High'
          uint64  :reserved2,            label: 'Reserved',             initial_value: 0x00000000000000000000
        end

        # Represents the specific layout of the DataBlock for a {ReadAndxResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          uint8  :pad,  label: 'Pad' # This field is optional. When using the NT LAN Manager dialect, this field can be used to align the Data field to a 16-bit boundary relative to the start of the SMB Header. If Unicode strings are being used, this field MUST be present. When used, this field MUST be one padding byte long.
          string :data, label: 'Data', read_length: lambda { self.parent.parameter_block.data_length }
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_READ_ANDX
        end

      end
    end
  end
end
