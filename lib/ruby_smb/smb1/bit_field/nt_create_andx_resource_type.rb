module RubySMB
  module SMB1
    module BitField
      # The ResourceType bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Response as defined in
      # [2.2.4.64.2 Response](https://msdn.microsoft.com/en-us/library/ee441612.aspx)
      class NtCreateAndxResourceType < BinData::Record
        endian  :little
        # When no bits are set, it is a file or directory
        bit5    :reserved,                    label: 'Reserved Space'
        bit1    :file_type_comm_device,       label: 'File Type Comm Device'
        virtual :file_type_printer,           label: 'File Type Printer', value: lambda { file_type_byte_mode_pipe & file_type_message_mode_pipe }
        bit1    :file_type_message_mode_pipe, label: 'File Type Message Mode Pipe'
        bit1    :file_type_byte_mode_pipe,    label: 'File Type Byte Mode Pipe'
        # byte boundary
        bit8    :reserved2,                   label: 'Reserved Space'
      end
    end
  end
end
