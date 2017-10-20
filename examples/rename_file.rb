#!/usr/bin/ruby

# This example script is used for testing the deleting of a file.
# It will attempt to connect to a specific share and then rename a specified file.
# Example usage: ruby rename_file.rb 192.168.172.138 msfadmin msfadmin TEST_SHARE short.txt shortrenamed.txt
# This will try to connect to \\192.168.172.138\TEST_SHARE with the msfadmin:msfadmin credentials
# and rename the file short.txt

require 'bundler/setup'
require 'ruby_smb'

address  = ARGV[0]
username = ARGV[1]
password = ARGV[2]
share    = ARGV[3]
filename = ARGV[4]
new_name = ARGV[5]
path     = "\\\\#{address}\\#{share}"

sock = TCPSocket.new address, 445
dispatcher = RubySMB::Dispatcher::Socket.new(sock)

client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, username: username, password: password)

protocol = client.negotiate
status = client.authenticate

puts "#{protocol} : #{status}"

begin
  tree = client.tree_connect(path)
  puts "Connected to #{path} successfully!"
rescue StandardError => e
  puts "Failed to connect to #{path}: #{e.message}"
end

if protocol == 'SMB1'
  data = tree.rename(filename, new_name)
else
  file = tree.open_file(filename: filename, write: true, delete: true)
  data = file.rename(new_name)
end

puts data
file.close if file
