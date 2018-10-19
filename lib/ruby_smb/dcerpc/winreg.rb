module RubySMB
  module Dcerpc
    module Winreg

      UUID = '338CD001-2244-31F1-AAAA-900038001003'
      VER_MAJOR = 1
      VER_MINOR = 0

      # Operation numbers
      OPEN_HKCR             = 0x00
      OPEN_HKCU             = 0x01
      OPEN_HKLM             = 0x02
      OPEN_HKPD             = 0x03
      OPEN_HKU              = 0x04
      REG_CLOSE_KEY         = 0x05
      REG_ENUM_KEY          = 0x09
      REG_ENUM_VALUE        = 0x0a
      REG_OPEN_KEY          = 0x0f
      REG_QUERY_INFO_KEY    = 0x10
      REG_QUERY_VALUE       = 0x11
      OPEN_HKCC             = 0x1b
      OPEN_HKPT             = 0x20
      OPEN_HKPN             = 0x21

      require 'ruby_smb/dcerpc/winreg/regsam'
      require 'ruby_smb/dcerpc/winreg/open_root_key_request'
      require 'ruby_smb/dcerpc/winreg/open_root_key_response'
      require 'ruby_smb/dcerpc/winreg/close_key_request'
      require 'ruby_smb/dcerpc/winreg/close_key_response'
      require 'ruby_smb/dcerpc/winreg/enum_key_request'
      require 'ruby_smb/dcerpc/winreg/enum_key_response'
      require 'ruby_smb/dcerpc/winreg/enum_value_request'
      require 'ruby_smb/dcerpc/winreg/enum_value_response'
      require 'ruby_smb/dcerpc/winreg/open_key_request'
      require 'ruby_smb/dcerpc/winreg/open_key_response'
      require 'ruby_smb/dcerpc/winreg/query_info_key_request'
      require 'ruby_smb/dcerpc/winreg/query_info_key_response'
      require 'ruby_smb/dcerpc/winreg/query_value_request'
      require 'ruby_smb/dcerpc/winreg/query_value_response'

      ROOT_KEY_MAP = {
        "HKEY_CLASSES_ROOT"         => OPEN_HKCR,
        "HKCR"                      => OPEN_HKCR,
        "HKEY_CURRENT_USER"         => OPEN_HKCU,
        "HKCU"                      => OPEN_HKCU,
        "HKEY_LOCAL_MACHINE"        => OPEN_HKLM,
        "HKLM"                      => OPEN_HKLM,
        "HKEY_USERS"                => OPEN_HKU,
        "HKU"                       => OPEN_HKU,
        "HKEY_PERFORMANCE_DATA"     => OPEN_HKPD,
        "HKPD"                      => OPEN_HKPD,
        "HKEY_CURRENT_CONFIG"       => OPEN_HKCC,
        "HKCC"                      => OPEN_HKCC,
        "HKEY_PERFORMANCE_TEXT"     => OPEN_HKPT,
        "HKPT"                      => OPEN_HKPT,
        "HKEY_PERFORMANCE_NLS_TEXT" => OPEN_HKPN,
        "HKPN"                      => OPEN_HKPN
      }

      def open_root_key(root_key)
        root_key_opnum = RubySMB::Dcerpc::Winreg::ROOT_KEY_MAP[root_key]
        raise ArgumentError, "Unknown Root Key: #{root_key}" unless root_key_opnum

        root_key_request_packet = OpenRootKeyRequest.new(opnum: root_key_opnum)
        response = dcerpc_request(root_key_request_packet)

        begin
          root_key_response_packet = OpenRootKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading OpenRootKeyResponse (command = #{root_key_opnum})"
        end
        unless root_key_response_packet.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when opening root key #{root_key}: #{WindowsError::NTStatus.find_by_retval(root_key_response_packet.error_status).join(',')}"
        end

        root_key_response_packet.ph_key
      end

      def open_key(handle, sub_key)
        openkey_request_packet = RubySMB::Dcerpc::Winreg::OpenKeyRequest.new(hkey: handle, lp_sub_key: sub_key)
        openkey_request_packet.sam_desired.read_control = 1
        openkey_request_packet.sam_desired.key_query_value = 1
        openkey_request_packet.sam_desired.key_enumerate_sub_keys = 1
        openkey_request_packet.sam_desired.key_notify = 1
        response = dcerpc_request(openkey_request_packet)
        begin
          open_key_response = RubySMB::Dcerpc::Winreg::OpenKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the OpenKey response"
        end
        unless open_key_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when opening sub-key #{sub_key}: #{WindowsError::NTStatus.find_by_retval(open_key_response.error_status).join(',')}"
        end

        open_key_response.phk_result
      end

      def query_value(handle, value_name)
        query_value_request_packet = RubySMB::Dcerpc::Winreg::QueryValueRequest.new(hkey: handle, lp_value_name: value_name)
        query_value_request_packet.lp_data.referent_identifier = 0
        response = dcerpc_request(query_value_request_packet)
        begin
          query_value_response = RubySMB::Dcerpc::Winreg::QueryValueResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the QueryValue response"
        end
        unless query_value_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when reading value #{value_name}: #{WindowsError::NTStatus.find_by_retval(query_value_response.error_status).join(',')}"
        end

        query_value_request_packet = RubySMB::Dcerpc::Winreg::QueryValueRequest.new(hkey: handle, lp_value_name: value_name)
        query_value_request_packet.lpcb_data = query_value_response.lpcb_data
        query_value_request_packet.lp_data.max_count = query_value_response.lpcb_data
        response = dcerpc_request(query_value_request_packet)
        begin
          query_value_response = RubySMB::Dcerpc::Winreg::QueryValueResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the QueryValue response"
        end
        unless query_value_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when reading value #{value_name}: #{WindowsError::NTStatus.find_by_retval(query_value_response.error_status).join(',')}"
        end

        query_value_response.data
      end

      def close_key(handle)
        close_key_request_packet = RubySMB::Dcerpc::Winreg::CloseKeyRequest.new(hkey: handle)
        response = dcerpc_request(close_key_request_packet)
        begin
          close_key_response = RubySMB::Dcerpc::Winreg::CloseKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the CloseKey response"
        end
        unless close_key_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when closing the key: #{WindowsError::NTStatus.find_by_retval(close_key_response.error_status).join(',')}"
        end

        close_key_response.error_status
      end

      def query_info_key(handle)
        query_info_key_request_packet = RubySMB::Dcerpc::Winreg::QueryInfoKeyRequest.new(hkey: handle)
        response = dcerpc_request(query_info_key_request_packet)
        begin
          query_info_key_response = RubySMB::Dcerpc::Winreg::QueryInfoKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the query_infoKey response"
        end
        unless query_info_key_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when querying information: #{WindowsError::NTStatus.find_by_retval(query_info_key_response.error_status).join(',')}"
        end

        query_info_key_response
      end

      def enum_key(handle, index)
        enum_key_request_packet = RubySMB::Dcerpc::Winreg::EnumKeyRequest.new(hkey: handle, dw_index: index)
        enum_key_request_packet.lpft_last_write_time = 0
        enum_key_request_packet.lp_name.maximum_length = 512
        enum_key_request_packet.lp_name.buffer.ndr_str.max_count = 256
        response = dcerpc_request(enum_key_request_packet)
        begin
          enum_key_response = RubySMB::Dcerpc::Winreg::EnumKeyResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the EnumKey response"
        end
        unless enum_key_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when enumerating the key: #{WindowsError::NTStatus.find_by_retval(enum_key_response.error_status).join(',')}"
        end

        enum_key_response.lp_name.to_s
      end

      def enum_value(handle, index)
        enum_value_request_packet = RubySMB::Dcerpc::Winreg::EnumValueRequest.new(hkey: handle, dw_index: index)
        enum_value_request_packet.lp_value_name.maximum_length = 512
        enum_value_request_packet.lp_value_name.buffer.ndr_str.max_count = 256
        enum_value_request_packet.lp_data.referent_identifier = 0
        response = dcerpc_request(enum_value_request_packet)
        begin
          enum_value_response = RubySMB::Dcerpc::Winreg::EnumValueResponse.read(response)
        rescue IOError
          raise RubySMB::Dcerpc::Error::InvalidPacket, "Error reading the Enumvalue response"
        end
        unless enum_value_response.error_status == WindowsError::NTStatus::STATUS_SUCCESS
          raise RubySMB::Dcerpc::Error::WinregError, "Error returned when enumerating values: #{WindowsError::NTStatus.find_by_retval(enum_value_response.error_status).join(',')}"
        end

        enum_value_response.lp_value_name.to_s
      end

      def read_registry_key(key, value_name)
        bind(endpoint: RubySMB::Dcerpc::Winreg)

        root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
        root_key_handle = open_root_key(root_key)
        subkey_handle = open_key(root_key_handle, sub_key)
        value = query_value(subkey_handle, value_name)
        close_key(subkey_handle)
        value
      end

      def enum_registry_key(key)
        bind(endpoint: RubySMB::Dcerpc::Winreg)

        root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
        root_key_handle = open_root_key(root_key)
        subkey_handle = if sub_key.nil? || sub_key.empty?
                          root_key_handle
                        else
                          open_key(root_key_handle, sub_key)
                        end
        query_info_key_response = query_info_key(subkey_handle)
        key_count = query_info_key_response.lpc_sub_keys.to_i
        enum_result = []
        key_count.times do |i|
          enum_result << enum_key(subkey_handle, i)
        end
        close_key(subkey_handle)
        enum_result
      end

      def enum_registry_values(key)
        bind(endpoint: RubySMB::Dcerpc::Winreg)

        root_key, sub_key = key.gsub(/\//, '\\').split('\\', 2)
        root_key_handle = open_root_key(root_key)
        subkey_handle = if sub_key.nil? || sub_key.empty?
                          root_key_handle
                        else
                          open_key(root_key_handle, sub_key)
                        end
        query_info_key_response = query_info_key(subkey_handle)
        value_count = query_info_key_response.lpc_values.to_i
        enum_result = []
        value_count.times do |i|
          enum_result << enum_value(subkey_handle, i)
        end
        close_key(subkey_handle)
        enum_result
      end

    end
  end
end

