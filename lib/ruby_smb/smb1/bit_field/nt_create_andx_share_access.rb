module RubySMB
  module SMB1
    module BitField
      # The ShareAccess bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class NtCreateAndxShareAccess < BinData::Record
        endian  :little
        # When no bits are set, sharing is not allowed (FILE_SHARE_NONE)
        bit5    :reserved,           label: 'Reserved Space'
        bit1    :file_share_delete,  label: 'File Share Delete'
        bit1    :file_share_write,   label: 'File Share Write'
        bit1    :file_share_read,    label: 'File Share Read'
        # Byte boundary
        bit24   :reserved2,          label: 'Reserved Space'
      end
    end
  end
end
