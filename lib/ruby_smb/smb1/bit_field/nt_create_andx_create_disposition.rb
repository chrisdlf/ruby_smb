module RubySMB
  module SMB1
    module BitField
      # The CreateDisposition bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class NtCreateAndxCreateDisposition < BinData::Record
        endian  :little
        # When no bits are set, the file should be overwritten or created if it does not exist (FILE_SUPERSEDE)
        bit5    :reserved,         label: 'Reserved Space'
        virtual :file_overwite_if, label: 'File Open If', value: lambda { file_open & file_overwrite }
        bit1    :file_overwrite,   label: 'File Overwrite'
        virtual :file_open_if,     label: 'File Open If', value: lambda { file_open & file_create }
        bit1    :file_create,      label: 'File Create'
        bit1    :file_open,        label: 'File Open'
        # Byte boundary
        bit24   :reserved2,        label: 'Reserved Space'

      end
    end
  end
end
