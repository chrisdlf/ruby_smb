module RubySMB
  module SMB1
    module Packet
      module Trans

        # A Trans TRANSACT_NMPIPE Request Packet as defined in
        # [2.2.5.6.1 Request](https://msdn.microsoft.com/en-us/library/ee441832.aspx)
        class TransactNmpipeRequest < RubySMB::GenericPacket

          class ParameterBlock < RubySMB::SMB1::Packet::Trans::Request::ParameterBlock
          end

          class TransData < BinData::Record
            string  :write_data, label: 'Write Data'

            # Returns the length of the TransData struct in number of bytes
            def length
              self.do_num_bytes
            end
          end

          class DataBlock < RubySMB::SMB1::Packet::Trans::DataBlock
            # If SMB_FLAGS2_UNICODE is set in the Flags2 field of the SMB Header
            # (section 2.2.3.1) of the request, the name field MUST be a
            # null-terminated array of 16-bit Unicode characters which MUST be
            # aligned to start on a 2-byte boundary from the start of the SMB
            # header.
            # e.g.: "\\PIPE\\\x00".encode("utf-16le")
            string             :name,               label: 'Name',              initial_value: "\\PIPE\\\x00"
            string             :pad1,               length: lambda { pad1_length }
            string             :trans_parameters,   label: 'Trans Parameters'
            string             :pad2,               length: lambda { pad2_length }
            trans_data         :trans_data,         label: 'Trans Data'
          end

          smb_header        :smb_header
          parameter_block   :parameter_block
          data_block        :data_block


          def initialize_instance
            super
            smb_header.command = RubySMB::SMB1::Commands::SMB_COM_TRANSACTION
            parameter_block.total_parameter_count = 0x0000
            # TotalDataCount (2 bytes): This field MUST be set to the number of bytes that the client requests to write to the named pipe as part of the transaction.
            # parameter_block.total_data_count =
            parameter_block.max_parameter_count = 0x0000
            # The default MaxDataCount is set to 1024 bytes. This might be changed if necessary.
            parameter_block.max_data_count = 1024
            parameter_block.max_setup_count = 0x00
            parameter_block.flags.assign( {:reserved=>0, :no_response=>0, :disconnect=>0, :reserved2=>0} )
            parameter_block.timeout = 0x00000000
            parameter_block.parameter_count = 0x0000
            parameter_block.setup << RubySMB::SMB1::Packet::Trans::Subcommands::TRANSACT_NMPIPE
            # The default FID should be changed once instantiated
            parameter_block.setup << 0x0000
          end

          def set_fid(fid)
            raise ArgumentError, "FID must exist" if fid.nil?
            parameter_block.setup[1] = fid
          end
        end
      end
    end
  end
end
