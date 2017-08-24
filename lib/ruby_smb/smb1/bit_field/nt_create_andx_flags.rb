module RubySMB
  module SMB1
    module BitField
      # The Flags bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      # [2.2.4.9.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246332.aspx)
      class NtCreateAndxFlags < BinData::Record
        endian  :little
        bit3    :reserved,                             label: 'Reserved Space'
        bit1    :nt_create_request_extended_response,  label: 'NT Create Request Extended Response'
        bit1    :nt_create_open_target_dir,            label: 'NT Create Open Target Directory'
        bit1    :nt_create_request_opbatch,            label: 'NT Create Request Batch OpLock'
        bit1    :nt_create_request_oplock,             label: 'NT Create Request OpLock'
        bit25   :reserved2,                            label: 'Reserved Space'
      end
    end
  end
end
