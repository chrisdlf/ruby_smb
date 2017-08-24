module RubySMB
  module SMB1
    module BitField
      # The ImpersonationLevel bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      # [2.2.4.9.1 Client Request Extensions](https://msdn.microsoft.com/en-us/library/cc246332.aspx)
      class NtCreateAndxImpersonationLevel < BinData::Record
        endian  :little
        # When no bits are set, impersonation level is anonymous (SEC_ANONYMOUS)
        bit6    :reserved,                label: 'Reserved Space'
        virtual :security_delegation,     label: 'Security Delegation', value: lambda { security_identification & security_impersonation }
        bit1    :security_impersonation,  label: 'Security Impersonation'
        bit1    :security_identification, label: 'Security Identification'
        # Byte boundary
        bit24   :reserved2,               label: 'Reserved Space'
      end
    end
  end
end
