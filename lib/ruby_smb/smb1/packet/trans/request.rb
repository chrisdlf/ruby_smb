module RubySMB
  module SMB1
    module Packet
      module Trans

        # This class represents a generic SMB1 Trans Request Packet as defined in
        # [2.2.4.33.1 Request](https://msdn.microsoft.com/en-us/library/ee441730.aspx)
        class Request < RubySMB::GenericPacket

          class ParameterBlock < RubySMB::SMB1::ParameterBlock
            uint16        :total_parameter_count, label: 'Total Parameter Count(bytes)'
            uint16        :total_data_count,      label: 'Total Data Count(bytes)',        value: lambda { data_count }
            uint16        :max_parameter_count,   label: 'Max Parameter Count(bytes)'
            uint16        :max_data_count,        label: 'Max Data Count(bytes)'
            uint8         :max_setup_count,       label: 'Max Setup Count'
            uint8         :reserved,              label: 'Reserved Space',                 value: 0x00
            trans_flags   :flags
            uint32        :timeout,               label: 'Timeout',                        initial_value: 0x00000000
            uint16        :reserved2,             label: 'Reserved Space',                 value: 0x0000
            uint16        :parameter_count,       label: 'Parameter Count(bytes)',         value: lambda { self.parent.data_block.trans_parameters.length }
            uint16        :parameter_offset,      label: 'Parameter Offset',               value: lambda { self.parent.data_block.trans_parameters.abs_offset }
            uint16        :data_count,            label: 'Data Count(bytes)',              value: lambda { self.parent.data_block.trans_data.length }
            uint16        :data_offset,           label: 'Data Offset',                    value: lambda { self.parent.data_block.trans_data.abs_offset }
            uint8         :setup_count,           label: 'Setup Count',                    value: lambda { setup.length }
            uint8         :reserved3,             label: 'Reserved Space',                 value: 0x00
            array         :setup,                 type: :uint16,                           initial_length: :setup_count
          end

          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            string :name,               label: 'Name',              initial_value: "\\PIPE\\\x00"
            string :pad1,               read_length: lambda { pad1_length }
            string :trans_parameters,   label: 'Trans Parameters'
            string :pad2,               read_length: lambda { pad2_length }
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
