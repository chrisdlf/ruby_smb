module RubySMB
  module SMB1
    module Packet

      # A SMB1 SMB_COM_NT_CREATE_ANDX Request Packet as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class NtCreateAndxRequest < RubySMB::GenericPacket

        # A SMB1 Parameter Block as defined by the {NtCreateAndxRequest}
        class ParameterBlock < RubySMB::SMB1::ParameterBlock
          endian :little
          uint8                              :andx_command,        label: 'AndX Command',       initial_value: 0xFF
          uint8                              :andx_reserved,       label: 'AndX Reserved',      initial_value: 0x00
          uint16                             :andx_offset,         label: 'AndX Offset',        value: lambda { get_andx_offset }
          uint8                              :reserved,            label: 'Reserved',           initial_value: 0x00
          uint16                             :name_length,         label: 'Name Length(bytes)', value: lambda { self.parent.data_block.file_name.length } # apparently, it is the filename length without the left padding and without null terminator
          nt_create_andx_flags               :flags,               label: 'Flags'
          uint32                             :root_directory_fid,  label: 'Root Directory FID'
          nt_create_andx_desired_access      :desired_access,      label: 'Desire dAccess'
          uint64                             :allocation_size,     label: 'Allocation Size'
          smb_ext_file_attributes            :ext_file_attributes, label: 'Extented File Attributes'
          nt_create_andx_share_access        :share_access,        label: 'Share Access'
          nt_create_andx_create_disposition  :create_disposition,  label: 'Create Disposition'
          nt_create_andx_create_options      :create_options,      label: 'Create Options'
          nt_create_andx_impersonation_level :impersonation_level, label: 'Impersonation Level'
          nt_create_andx_security_flags      :security_flags,      label: 'Security Flags'

          def get_andx_offset
            if andx_command == 0xFF
              return 0x00
            else
              # TODO: the offset in bytes from the start of the SMB Header (section 2.2.3.1) to the start of the WordCount field in the next SMB command in this packet.
              return 0x00
            end
          end

        end

        # Represents the specific layout of the DataBlock for a {SessionSetupRequest} Packet.
        class DataBlock < RubySMB::SMB1::DataBlock
          string :file_name, label: 'File Name'
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
