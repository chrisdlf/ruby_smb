module RubySMB
  module SMB1
    module BitField
      # The WriteMode bit-field for an SMB1 SMB_COM_WRITE_ANDX Response as defined in
      # [2.2.4.43.1 Request](https://msdn.microsoft.com/en-us/library/ee441954.aspx)
      class WriteAndxWriteMode < BinData::Record
        endian  :little
        bit4    :reserved,             label: 'Reserved Space'
        bit1    :msg_start,            label: 'Message Start'
        bit1    :raw_mode,             label: 'Raw Mode'
        bit1    :read_bytes_available, label: 'Read Bytes Available'
        bit1    :writethrough_mode,    label: 'Writethrough Mode'
        # byte boundary
        bit8    :reserved2,            label: 'Reserved Space'
      end
    end
  end
end
