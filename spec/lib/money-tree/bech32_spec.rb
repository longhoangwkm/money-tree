require 'spec_helper'

describe MoneyTree::Bech32 do
  VALID_CHECKSUM = [
      "A12UEL5L",
      "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
      "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
      "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
      "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
  ]

  INVALID_CHECKSUM = [
      " 1nwldj5",
      "\x7F" + "1axkwrx",
      "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
      "pzry9x0s0muk",
      "1pzry9x0s0muk",
      "x1b4n0q5v",
      "li1dgmt3",
      "de1lg7wt\xff",
  ]

  it 'valid checksum' do
    VALID_CHECKSUM.each do |bech|
      hrp, _ = MoneyTree::Bech32.decode(bech)
      expect(hrp).to be_truthy
      pos = bech.rindex('1')
      bech = bech[0..pos] + (bech[pos + 1].ord ^ 1).chr + bech[pos+2..-1]
      hrp, _ = MoneyTree::Bech32.decode(bech)
      expect(hrp).to be_nil
    end
  end

  it 'invalid checksum' do
    INVALID_CHECKSUM.each do |bech|
      hrp, _ = MoneyTree::Bech32.decode(bech)
      expect(hrp).to be_nil
    end
  end
end
