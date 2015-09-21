require 'spec_helper'

module RubySMB
module SMB1
module Packet
RSpec.describe Leaf_Field do

  describe 'Leaf_Field' do
    field = Leaf_Field.new

    it 'is a kind of Field' do
      expect(field.kind_of? Field).to eql true
    end
  end

  context 'Leaf_Field.new() - no args' do
    let(:field) { Leaf_Field.new }

    # attr
    describe '#name' do
      it 'returns the default name: empty string' do
        expect(field.name).to eql ''
      end
    end

    # attr
    describe '#n_bytes' do
      it 'calculates :n_bytes from padded default value: empty string' do
        expect(field.n_bytes).to eql 0
      end
    end

    # attr
    describe '#n_bytes_spec' do
      it 'returns the default n_bytes_spec: 0' do
        expect(field.n_bytes).to eql 0
      end
    end

    # attr
    describe '#value' do
      it 'returns default value: empty string' do
        expect(field.value).to eql ''
      end
    end

    # behavior
    describe '#to_binary_s' do
      it 'calculates binary string from padded default value: empty string' do
        expect(field.to_binary_s).to eql ''
      end
    end
  end

  context 'Leaf_Field.new { } - block given' do
    describe '#name=' do
      it 'sets attr:name' do
        field = Leaf_Field.new { |f| f.name = :of_hemp }
        expect(field.name).to eql :of_hemp
      end
    end

    describe '#n_bytes' do
      let(:field) { Leaf_Field.new { |f| f.value = "1234" } }

      it 'returns the number of bytes of attr:value' do
        expect(field.n_bytes).to eql 4
      end
    end

    describe '#n_bytes_spec' do
      let(:field) { Leaf_Field.new { |f| f.n_bytes_spec = 2 } }

      it 'returns the number of bytes of attr:value' do
        expect(field.n_bytes_spec).to eql 2
      end
    end

    describe '#value=' do
      let(:field) { Leaf_Field.new { |f| f.value = "\x02Foo\x00" } }

      it 'sets attr:value' do
        expect(field.value).to eql "\x02Foo\x00"
      end
    end

    describe 'to_binary_s' do
      let(:field) { Leaf_Field.new do |f|
                      f.n_bytes_spec = 8
                      f.value        = "\x02Foo\x00"
                    end }

      it 'renders :value to a padded binary string' do
        expect(field.to_binary_s).to eql "\x02Foo\x00\x00\x00\x00"
      end
    end


  end
end
end
end
end
