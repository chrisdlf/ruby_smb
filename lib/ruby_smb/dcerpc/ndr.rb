module RubySMB
  module Dcerpc
    module Ndr

      # NDR Syntax
      UUID = '8a885d04-1ceb-11c9-9fe8-08002b104860'
      VER_MAJOR = 2
      VER_MINOR = 0

      class NdrString < BinData::Primitive
        endian :little

        uint32    :max_count
        uint32    :offset,     initial_value: 0
        uint32    :actual_count
        stringz16 :str,        read_length: -> { actual_count }, onlyif: -> { actual_count > 0 }
        #stringz16 :terminator, value: "",                        onlyif: -> { !str.empty? }

        def get
          self.actual_count == 0 ? 0 : self.str
        end

        def set(v)
          if v.is_a?(Integer) && v == 0
            self.actual_count = 0
          else
            self.str = v
            self.max_count = self.actual_count = str.to_binary_s.size / 2
          end
        end
      end

      class NdrLpStr < BinData::Primitive
        endian :little

        uint32     :referent_identifier, initial_value: 0x00020000
        ndr_string :ndr_str,             onlyif: -> { referent_identifier != 0 }

        def get
          referent_identifier == 0 ? 0 : self.ndr_str
        end

        def set(v)
          if v.is_a?(Integer) && v == 0
            self.referent_identifier = v
          else
            self.ndr_str = v
          end
        end

        def to_s
          self.referent_identifier == 0 ? "\0" : self.ndr_str
        end
      end

      class NdrContextHandle < BinData::Primitive
        endian :little
        #uint32 :context_handle_attributes, initial_value: -> { handle[:context_handle_attributes] }
        uint32 :context_handle_attributes
        uuid   :context_handle_uuid

        def get
          {:context_handle_attributes => context_handle_attributes, :context_handle_uuid => context_handle_uuid}
        end

        def set(handle)
          if handle.is_a?(Hash)
            self.context_handle_attributes = handle[:context_handle_attributes]
            self.context_handle_uuid = handle[:context_handle_uuid]
          elsif handle.is_a?(NdrContextHandle)
            read(handle.to_binary_s)
          else
            read(handle.to_s)
          end
        end
      end

      class NdrLpDword < BinData::Primitive
        endian :little

        uint32 :referent_identifier, initial_value: 0x00020000
        uint32 :dword

        def get
          self.dword
        end

        def set(v)
          self.dword = v
        end
      end

      class NdrLpByte < BinData::Record
        endian :little

        uint32 :referent_identifier, initial_value: 0x00020000
        uint32 :max_count, initial_value: -> { actual_count }, onlyif: -> { referent_identifier != 0 }
        uint32 :offset,     initial_value: 0, onlyif: -> { referent_identifier != 0 }
        uint32 :actual_count, initial_value: -> { bytes.size }, onlyif: -> { referent_identifier != 0 }
        array  :bytes, :type => :uint8, initial_length: -> { actual_count }, onlyif: -> { referent_identifier != 0 }
      end

      class NdrLpFileTime < BinData::Primitive
        endian :little

        uint32    :referent_identifier, initial_value: 0x00020000
        file_time :file_time,           onlyif: -> { referent_identifier != 0 }

        def get
          referent_identifier == 0 ? 0 : self.file_time
        end

        def set(v)
          if v.is_a?(Integer) && v == 0
            self.referent_identifier = v
          else
            self.file_time = v
          end
        end
      end

    end
  end

end
