module RubySMB
  module SMB1
    module BitField
      # The CreateOptions bit-field for an SMB1 SMB_COM_NT_CREATE_ANDX Request as defined in
      # [2.2.4.64.1 Request](https://msdn.microsoft.com/en-us/library/ee442175.aspx)
      class NtCreateAndxCreateOptions < BinData::Record
        endian  :little
        # When no bits are set, the file should be overwritten or created if it does not exist (FILE_SUPERSEDE)
        bit1    :file_create_tree_connection,    label: 'File Create Tree Connection'
        bit1    :file_non_directory_file,        label: 'File Non Directory File'
        bit1    :file_synchronous_io_nonalert,   label: 'File Synchronous IO Nonalert'
        bit1    :file_synchronous_io_alert,      label: 'File Synchronous IO Alert'
        bit1    :file_no_intermediate_buffering, label: 'File No Intermediate Buffering'
        bit1    :file_sequential_only,           label: 'File Sequential Only'
        bit1    :file_write_through,             label: 'File Write Through'
        bit1    :file_directory_file,            label: 'File Directory File'
        # Byte boundary
        bit1    :file_no_compression,            label: 'File No Compression'
        bit1    :file_open_for_backup_intent,    label: 'File Open For Backup Intent'
        bit1    :file_open_by_file_id,           label: 'File Open By File ID'
        bit1    :file_delete_on_close,           label: 'File Delete On Close'
        bit1    :file_random_access,             label: 'File Random Access'
        bit1    :file_open_for_recovery,         label: 'File Open For Recovery'
        bit1    :file_no_ea_knowledge,           label: 'File No EA Knowledge'
        bit1    :file_complete_if_oplocked,      label: 'File Complete If OpLocked'
        # Byte boundary
        bit4    :reserved,                       label: 'Reserved Space'
        bit1    :file_open_for_free_space_query, label: 'File Open For Free Space Query'
        bit1    :file_open_no_recall,            label: 'File Open No Recall'
        bit1    :file_open_reparse_point,        label: 'File Open Reparse Point'
        bit1    :file_reserve_opfilter,          label: 'File Reserve Opfilter'
        # Byte boundary
        bit8    :reserved3,                      label: 'Reserved Space'

      end
    end
  end
end
