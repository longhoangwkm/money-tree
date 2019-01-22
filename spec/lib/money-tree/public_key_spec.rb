require 'spec_helper'

describe MoneyTree::PublicKey do

  describe "with a private key" do
    before do
      @private_key = MoneyTree::PrivateKey.new key: "5eae5375fb5f7a0ea650566363befa2830ef441bdcb19198adf318faee86d64b"
      @key = MoneyTree::PublicKey.new @private_key
    end

    describe "to_hex(compressed: false)" do
      it "has 65 bytes" do
        expect(@key.uncompressed.to_hex.length).to eql(130)
      end

      it "is a valid hex" do
        expect(@key.uncompressed.to_hex).to eql('042dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b11203096f1a1c5276a73f91b9465357004c2103cc42c63d6d330df589080d2e4'      )
      end
    end

    describe "to_hex" do
      it "has 33 bytes" do
        expect(@key.to_hex.length).to eql(66)
      end

      it "is a valid compressed hex" do
        expect(@key.to_hex).to eql('022dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b'      )
      end
    end

    describe "to_fingerprint" do
      it "returns a valid fingerprint" do
        expect(@key.to_fingerprint).to eql("1fddf42e")
      end
    end

    describe "to_address(compressed: false)" do
      it "has 34 characters" do
        expect(@key.uncompressed.to_address.length).to eql(34)
      end

      it "is a valid bitcoin address" do
        expect(@key.uncompressed.to_address).to eql('133bJA2xoVqBUsiR3uSkciMo5r15fLAaZg'      )
      end
    end

    describe "to_compressed_address" do
      it "has 34 characters" do
        expect(@key.to_address.length).to eql(34)
      end

      it "is a valid compressed bitcoin address" do
        expect(@key.to_address).to eql('13uVqa35BMo4mYq9LiZrXVzoz9EFZ6aoXe'      )
      end
    end
  end

  describe "without a private key" do
    before do
      @key = MoneyTree::PublicKey.new '042dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b11203096f1a1c5276a73f91b9465357004c2103cc42c63d6d330df589080d2e4'
    end

    describe "to_hex(compressed: false)" do
      it "has 65 bytes" do
        expect(@key.uncompressed.to_hex.length).to eql(130)
      end

      it "is a valid hex" do
        expect(@key.uncompressed.to_hex).to eql('042dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b11203096f1a1c5276a73f91b9465357004c2103cc42c63d6d330df589080d2e4'      )
      end
    end

    describe "to_hex" do
      it "has 33 bytes" do
        expect(@key.compressed.to_hex.length).to eql(66)
      end

      it "is a valid compressed hex" do
        expect(@key.compressed.to_hex).to eql('022dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b'      )
      end
    end

    describe "to_fingerprint" do
      it "returns a valid fingerprint" do
        expect(@key.compressed.to_fingerprint).to eql("1fddf42e")
      end
    end

    describe "to_address(compressed: false)" do
      it "has 34 characters" do
        expect(@key.uncompressed.to_address.length).to eql(34)
      end

      it "is a valid bitcoin address" do
        expect(@key.uncompressed.to_address).to eql('133bJA2xoVqBUsiR3uSkciMo5r15fLAaZg'      )
      end
    end

    describe "to_compressed_address" do
      it "has 34 characters" do
        expect(@key.compressed.to_address.length).to eql(34)
      end

      it "is a valid compressed bitcoin address" do
        expect(@key.compressed.to_address).to eql('13uVqa35BMo4mYq9LiZrXVzoz9EFZ6aoXe'      )
      end
    end

    describe "#compression" do
      it "returns current compression setting" do
        @key.compression = :uncompressed
        expect(@key.compression).to eql(:uncompressed)
        @key.compression = :compressed
        expect(@key.compression).to eql(:compressed)
      end
    end
  end

  describe "#to_address witness_v0_address" do
    before do
      @pub_key = MoneyTree::PublicKey.new("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
    end

    it "is a valid bech32 bitcoin address" do
      expect(@pub_key.to_address(network: :bitcoin, format: :p2wpkh)).to eq('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4')
    end

    it "is a valid bech32 bitcoin testnet address" do
      expect(@pub_key.to_address(network: :bitcoin_testnet, format: :p2wpkh)).to eq('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx')
    end

    it "is a valid bech32 xpchain address" do
      expect(@pub_key.to_address(network: :xpchain, format: :p2wpkh)).to eq('xpc1qw508d6qejxtdg4y5r3zarvary0c5xw7k94ck4t')
    end
  end

  describe "with a bad key" do
    it "raises KeyFormatNotFound" do
      expect { @key = MoneyTree::PublicKey.new 'THISISNOTAVALIDKEY' }.to raise_error(MoneyTree::Key::KeyFormatNotFound)
    end
  end

  describe "recalcuating public key" do
    it "produces same results" do
      results = []
      100.times do
        results << MoneyTree::PublicKey.new('042dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b11203096f1a1c5276a73f91b9465357004c2103cc42c63d6d330df589080d2e4').to_s
      end
      expect(results.uniq.length).to eql(1)
    end
  end

  describe "#uncompressed" do
    before do
      @key = MoneyTree::PublicKey.new('022dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b')
    end

    it "does not mutate key" do
      before_str = @key.to_s
      @key.uncompressed
      after_str = @key.to_s
      expect(before_str).to eql(after_str)
    end
  end

  describe "#compressed" do
    before do
      @key = MoneyTree::PublicKey.new('042dfc2557a007c93092c2915f11e8aa70c4f399a6753e2e908330014091580e4b11203096f1a1c5276a73f91b9465357004c2103cc42c63d6d330df589080d2e4')
    end

    it "does not mutate key" do
      before_str = @key.to_s
      @key.compressed
      after_str = @key.to_s
      expect(before_str).to eql(after_str)
    end
  end

  context "testnet" do
    context 'with private key' do
      before do
        @private_key = MoneyTree::PrivateKey.new
        @key = MoneyTree::PublicKey.new(@private_key)
      end

      it "should have an address starting with m or n" do
        expect(%w(m n)).to include(@key.to_s(network: :bitcoin_testnet)[0])
      end

      it "should have an uncompressed address starting with m or n" do
        expect(%w(m n)).to include(@key.uncompressed.to_s(network: :bitcoin_testnet)[0])
      end
    end

    context 'without private key' do
      before do
        @key = MoneyTree::PublicKey.new('0297b033ba894611345a0e777861237ef1632370fbd58ebe644eb9f3714e8fe2bc')
      end

      it "should have an address starting with m or n" do
        expect(%w(m n)).to include(@key.to_s(network: :bitcoin_testnet)[0])
      end
    end
  end
end
