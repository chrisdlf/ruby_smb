module RubySMB
  module Fscc
    # Contains the Constant values for File Information Classes, as defined in
    # [2.4 File Information Classes](https://msdn.microsoft.com/en-us/library/cc232064.aspx)
    module FileInformation
      require 'ruby_smb/fscc/file_information/file_directory_information'
      require 'ruby_smb/fscc/file_information/file_full_directory_information'
      require 'ruby_smb/fscc/file_information/file_disposition_information'
      require 'ruby_smb/fscc/file_information/file_id_full_directory_information'
      require 'ruby_smb/fscc/file_information/file_both_directory_information'
      require 'ruby_smb/fscc/file_information/file_id_both_directory_information'
      require 'ruby_smb/fscc/file_information/file_names_information'
      require 'ruby_smb/fscc/file_information/file_rename_information'

      FILE_DIRECTORY_INFORMATION         = 0x01
      FILE_FULL_DIRECTORY_INFORMATION    = 0x02
      FILE_DISPOSITION_INFORMATION       = 0x0D
      FILE_ID_FULL_DIRECTORY_INFORMATION = 0x26
      FILE_BOTH_DIRECTORY_INFORMATION    = 0x03
      FILE_ID_BOTH_DIRECTORY_INFORMATION = 0x25
      FILE_NAMES_INFORMATION             = 0x0C
      FILE_RENAME_INFORMATION            = 0x0A

    end
  end
end
