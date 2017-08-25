module RubySMB
  module SMB1
    module Packet

      # A SMB1 SMB_COM_WRITE_ANDX Request Packet as defined in
      # [2.2.4.43.1 Request](https://msdn.microsoft.com/en-us/library/ee441954.aspx)
      # [2.2.4.3.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/ff469893.aspx)
      class WriteAndxRequest < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {WriteAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little
          uint8                              :andx_command,        label: 'AndX Command',       initial_value: 0xFF
          uint8                              :andx_reserved,       label: 'AndX Reserved',      initial_value: 0x00
          uint16                             :andx_offset,         label: 'AndX Offset',        value: lambda { get_andx_offset }
          uint16                             :fid,                 label: 'FID'
          uint32                             :offset,              label: 'Offset'
          uint32                             :timeout,             label: 'Timeout'
          write_andx_write_mode              :write_mode,          label: 'Write Mode'
          uint16                             :remaining,           label: 'Remaining'
          uint16                             :data_length_high,    label: 'Data Length High'
          uint16                             :data_length,         label: 'Data Length(bytes)', value: lambda { self.parent.data_block.data.length }
          uint16                             :data_offset,         label: 'Data Offset',        value: lambda {self.parent.data_block.data.abs_offset}
          uint32                             :offset_high,         label: 'Offset High'

          def get_andx_offset
            if andx_command == 0xFF
              return 0x00
            else
              # TODO: the offset in bytes from the start of the SMB Header (section 2.2.3.1) to the start of the WordCount field in the next SMB command in this packet.
              return 0x00
            end
          end

        end

        # Represents the specific layout of the DataBlock for a {WriteAndxRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          uint8  :pad,  label: 'Pad' # Windows 7 uses 0xEE as pad value (to confirm)
          string :data, label: 'Data'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_WRITE_ANDX
        end

      end
    end
  end
end
