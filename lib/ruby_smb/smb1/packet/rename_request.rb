module RubySMB
  module SMB1
    module Packet
      # A SMB1 SMB_COM_RENAME Request Packet as defined in
      # [2.2.4.8.1 Request](https://msdn.microsoft.com/en-us/library/ee442062.aspx)
      class RenameRequest < RubySMB::GenericPacket
        # A SMB1 Parameter Block as defined by the {RenameRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little

          smb_file_attributes :search_attributes, label: 'Search Attributes'
        end

        # Represents the specific layout of the DataBlock for a {RenameRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          endian :little
          
          uint8  :buffer_format1, label: 'Buffer Format 1', initial_value: 0x04
          string :old_file_name,  label: 'Old File Name'
          uint8  :buffer_format2, label: 'Buffer Format 2', initial_value: 0x04
          string :new_file_name,  label: 'New File Name'
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_RENAME
        end

      end
    end
  end
end
