module RubySMB
  module SMB1
    module BitField
      # The SecurityFlags bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class NtCreateAndxSecurityFlags < BinData::Record
        endian  :little
        # When no bits are set, impersonation level is anonymous (SEC_ANONYMOUS)
        bit6    :reserved,                      label: 'Reserved Space'
        bit1    :smb_security_effective_only,   label: 'SMB Security Effective Only'
        bit1    :smb_security_context_tracking, label: 'SMB Security Context Tracking'
      end
    end
  end
end
