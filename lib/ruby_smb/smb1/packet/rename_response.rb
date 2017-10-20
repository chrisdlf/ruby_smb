module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_RENAME Response Packet as defined in
      # [2.2.4.8.2 Response](https://msdn.microsoft.com/en-us/library/ee442158.aspx)
      class RenameResponse < RubySMB::GenericPacket
        # A SMB1 Parameter Block as defined by the {RenameResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
        end

        # Represents the specific layout of the DataBlock for a {RenameResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_RENAME
          smb_header.flags.reply = 1
        end
      end
    end
  end
end
