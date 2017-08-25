module RubySMB
  module SMB1
    module Packet
      module Trans

        # This class represents a generic SMB1 Trans Response Packet as defined in
        # [2.2.4.33.2 Response](https://msdn.microsoft.com/en-us/library/ee442061.aspx)
        class Response < RubySMB::GenericPacket

          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            uint16  :total_parameter_count,  label: 'Total Parameter Count(bytes)'
            uint16  :total_data_count,       label: 'Total Data Count(bytes)'
            uint16  :reserved,               label: 'Reserved Space'
            uint16  :parameter_count,        label: 'Parameter Count(bytes)'
            uint16  :parameter_offset,       label: 'Parameter Offset'
            uint16  :parameter_displacement, label: 'Parameter Displacement'
            uint16  :data_count,             label: 'Data Count(bytes)'
            uint16  :data_offset,            label: 'Data Offset'
            uint16  :data_displacement,      label: 'Data Displacement'
            uint8   :setup_count,            label: 'Setup Count'
            uint8   :reserved2,              label: 'Reserved Space'
            array   :setup,                  type: :uint16, initial_length: :setup_count
          end

          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            string :pad1,               length: lambda { pad1_length }
            string :trans_parameters,   label: 'Trans Parameters'
            string :pad2,               length: lambda { pad2_length }
            string :trans_data,         label: 'Trans Data'
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block

          def initialize_instance
            super
            smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION
          end

        end
      end
    end
  end
end
