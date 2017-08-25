module RubySMB
  module SMB1
    module Packet

      # A SMB1 SMB_COM_NT_CREATE_ANDX Response Packet as defined in
      # [2.2.4.64.2 Response](https://msdn.microsoft.com/en-us/library/ee441612.aspx)
      class NtCreateAndxResponse < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {NtCreateAndxResponse}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little
          uint8                              :andx_command,        label: 'AndX Command'
          uint8                              :andx_reserved,       label: 'AndX Reserved'
          uint16                             :andx_offset,         label: 'AndX Offset'
          nt_create_andx_oplock_level        :oplock_level,        label: 'OpLock Level'
          uint16                             :fid,                 label: 'FID'
          nt_create_andx_create_disposition  :create_disposition,  label: 'Create Disposition'
          file_time                          :create_time,         label: 'Create Time'
          file_time                          :last_access_time,    label: 'Last Access Time'
          file_time                          :last_write_time,     label: 'Last Write Time'
          file_time                          :last_change_time,    label: 'Last Change Time'
          smb_ext_file_attributes            :ext_file_attributes, label: 'Extented File Attributes'
          uint64                             :allocation_size,     label: 'Allocation Size'
          uint64                             :end_of_file,         label: 'End of File Offset'
          nt_create_andx_resource_type       :resource_type,       label: 'Resource Type'
          smb_nmpipe_status                  :nmpipe_status,       label: 'Named Pipe Status'
          uint8                              :directory,           label: 'Directory'
        end

        # Represents the specific layout of the DataBlock for a {SessionSetupResponse} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
        end

        smb_header        :smb_header
        parameter_block   :parameter_block
        data_block        :data_block

        def initialize_instance
          super
          smb_header.command = RubySMB::SMB1::Commands::SMB_COM_NT_CREATE_ANDX
        end

      end
    end
  end
end
