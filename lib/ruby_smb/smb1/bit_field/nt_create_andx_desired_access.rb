module RubySMB
  module SMB1
    module BitField
      # The DesiredAccess bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class NtCreateAndxDesiredAccess < BinData::Record
        endian  :little
        bit1    :file_read_attributes,   label: 'File Read Attributes'
        bit1    :reserved,               label: 'Reserved Space' # Wireshark has 'Delete Child: delete child access' for this bit
        bit1    :file_execute,           label: 'File Execute'
        bit1    :file_write_ea,          label: 'File Write Extended Attributes (EAs)'
        bit1    :file_read_ea,           label: 'File Read Extended Attributes (EAs)'
        bit1    :file_append_data,       label: 'File Append Data'
        bit1    :file_write_data,        label: 'File Write Data'
        bit1    :file_read_data,         label: 'File Read Data'
        # Byte boundary
        bit7    :reserved2,              label: 'Reserved Space'
        bit1    :file_write_attributes,  label: 'File Write Attributes'
        # Byte boundary
        bit3    :reserved3,              label: 'Reserved Space'
        bit1    :synchronize,            label: 'Synchronize'
        bit1    :write_owner,            label: 'Write Owner'
        bit1    :write_dac,              label: 'Write DACL'
        bit1    :read_control,           label: 'Read Control'
        bit1    :delete_or_rename,       label: 'Delete or Rename'
        # Byte boundary
        bit1    :generic_read,           label: 'Generic Read'
        bit1    :generic_write,          label: 'Generic Write'
        bit1    :generic_execute,        label: 'Generic Execute'
        bit1    :generic_all,            label: 'Generic All'
        bit2    :reserved4,              label: 'Reserved Space'
        bit1    :maximum_allowed,        label: 'Maximum Allowed'
        bit1    :access_system_security, label: 'Access System Security'
      end
    end
  end
end
