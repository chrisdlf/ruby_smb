module RubySMB
  module SMB1
    module BitField
      # The OpLockLevel bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Response as defined in
      # [2.2.4.64.2 Response](https://msdn.microsoft.com/en-us/library/ee441612.aspx)
      class NtCreateAndxOplockLevel < BinData::Record
        endian  :little
        # When no bits are set, no OpLock is granted
        bit6    :reserved,                      label: 'Reserved Space'
        virtual :level_2_oplock,   label: 'Level II OpLock', value: lambda { exclusive_oplock & batch_oplock }
        bit1    :exclusive_oplock, label: 'Exclusive OpLock'
        bit1    :batch_oplock,     label: 'Batch OpLock'
      end
    end
  end
end
