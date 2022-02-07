import 'package:chia_bls_dart/src/bls/extensions/byte_conversion.dart';
import 'package:chia_bls_dart/src/bls/hkdf.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  void testHKDF(String ikmHex, String saltHex, String infoHex,
      String prkExpectedHex, String okmExpectedHex, int L) {
    var ikm = ikmHex.hexToBytes();
    var salt = saltHex.hexToBytes();
    var info = infoHex.hexToBytes();
    var prkExpected = prkExpectedHex.hexToBytes();
    var okmExpected = okmExpectedHex.hexToBytes();
    var prk = HKDF256.extract(salt, ikm);
    var okm = HKDF256.expand(L, prk, info);

    expect(prkExpected.length, equals(32));
    expect(okmExpected.length, equals(L));

    for (int i = 0; i < 32; i++) {
      expect(prk[i], equals(prkExpected[i]));
    }

    for (int i = 0; i < L; i++) {
      expect(okm[i], equals(okmExpected[i]));
    }
  }

  group('RFC5869 Test Vectors', () {
    //https://datatracker.ietf.org/doc/html/rfc5869
    test('Test Case 1 - SHA256', () {
      testHKDF(
          "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
          "000102030405060708090a0b0c",
          "f0f1f2f3f4f5f6f7f8f9",
          "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
          "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
          42);
    });
    test('Test Case 2 - SHA256', () {
      testHKDF(
          "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f"
              "202122232425262728292a2b2c2d2e2f"
              "303132333435363738393a3b3c3d3e3f"
              "404142434445464748494a4b4c4d4e4f", // 80 octets
          "0x606162636465666768696a6b6c6d6e6f"
              "707172737475767778797a7b7c7d7e7f"
              "808182838485868788898a8b8c8d8e8f"
              "909192939495969798999a9b9c9d9e9f"
              "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", // 80 octets
          "0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
              "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
              "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
              "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
              "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", // 80 octets
          "0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", // 32 octets
          "0xb11e398dc80327a1c8e7f78c596a4934"
              "4f012eda2d4efad8a050cc4c19afa97c"
              "59045a99cac7827271cb41c65e590e09"
              "da3275600c2f09b8367793a9aca3db71"
              "cc30c58179ec3e87c14c01d5c1f3434f"
              "1d87", // 82 octets
          82);
    });
    test('Test Case 3 - SHA256', () {
      testHKDF(
          "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
          "",
          "",
          "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
          "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
          42);
    });
    test('Test Case 4 - Works with multiple of 32', () {
      // From Chia's test cases https://github.com/Chia-Network/bls-signatures/blob/main/src/test.cpp
      testHKDF(
          "8704f9ac024139fe62511375cf9bc534c0507dcf00c41603ac935cd5943ce0b4b88599390de14e743ca2f56a73a04eae13aa3f3b969b39d8701e0d69a6f8d42f",
          "53d8e19b",
          "",
          "eb01c9cd916653df76ffa61b6ab8a74e254ebfd9bfc43e624cc12a72b0373dee",
          "8faabea85fc0c64e7ca86217cdc6dcdc88551c3244d56719e630a3521063082c46455c2fd5483811f9520a748f0099c1dfcfa52c54e1c22b5cdf70efb0f3c676",
          64);
    });
  });
}
