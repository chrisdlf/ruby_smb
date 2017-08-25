module RubySMB
  module SMB1
    module Packet

      # A SMB1 SMB_COM_READ_ANDX Request Packet as defined in
      # [2.2.4.42.1 Request](https://msdn.microsoft.com/en-us/library/ee441839.aspx)
      # [2.2.4.2.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/ff470250.aspx)
      class ReadAndxRequest < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {ReadAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian  :little
          uint8   :andx_command,                 label: 'AndX Command',       initial_value: 0xFF
          uint8   :andx_reserved,                label: 'AndX Reserved',      initial_value: 0x00
          uint16  :andx_offset,                  label: 'AndX Offset',        value: lambda { get_andx_offset }
          uint16  :fid,                          label: 'FID'
          uint32  :offset,                       label: 'Offset'
          uint16  :max_count_of_bytes_to_return, label: 'Max Count of Bytes to Return'
          uint16  :min_count_of_bytes_to_return, label: 'Min Count of Bytes to Return'
          uint32  :timeout_or_max_count_high,    label: 'Timeout or MaxCountHigh' # TODO: improve this (see [2.2.4.2.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/ff470250.aspx))
          uint16  :remaining,                    label: 'Remaining'
          uint32  :offset_high,                  label: 'Offset High'

          def get_andx_offset
            if andx_command == 0xFF
              return 0x00
            else
              # TODO: the offset in bytes from the start of the SMB Header (section 2.2.3.1) to the start of the WordCount field in the next SMB command in this packet.
              return 0x00
            end
          end

        end

        # Represents the specific layout of the DataBlock for a {ReadAndxRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
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
