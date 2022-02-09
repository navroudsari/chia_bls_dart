import 'dart:math';

import 'package:chia_bls_dart/src/bls/curve/ec.dart';
import 'package:chia_bls_dart/src/bls/extensions/byte_conversion.dart';
import 'package:chia_bls_dart/src/bls/fields.dart';
import 'package:chia_bls_dart/src/bls/hd_keys.dart';
import 'package:chia_bls_dart/src/bls/hkdf.dart';
import 'package:chia_bls_dart/src/bls/private_key.dart';
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

  group('private key tests', () {
    test('Copy {constructor| assignment operator}', () {
      PrivateKey pk1 =
          PrivateKey.fromBytes(Random.secure().nextInt(255).asUint32Bytes());
      PrivateKey pk2 =
          PrivateKey.fromBytes(Random.secure().nextInt(255).asUint32Bytes());
      PrivateKey pk3 = pk2.clone();
      expect(pk1.isZero(), isFalse);
      expect(pk2.isZero(), isFalse);
      expect(pk3.isZero(), isFalse);
      expect(pk1, isNot(equals(pk2)));
      expect(pk3, equals(pk2));
      pk2 = pk1;
      expect(pk1, equals(pk2));
      expect(pk3, isNot(equals(pk2)));
    });

    test('Equality operators', () {
      PrivateKey pk1 =
          PrivateKey.fromBytes(Random.secure().nextInt(255).asUint32Bytes());
      PrivateKey pk2 =
          PrivateKey.fromBytes(Random.secure().nextInt(255).asUint32Bytes());
      var pk3 = pk2;
      expect(pk1, isNot(equals(pk2)));
      expect(pk1, isNot(equals(pk3)));
      expect(pk2, equals(pk3));
    });
  });

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

  group('EIP-2333 test vectors', () {
    // Test vectors are taken from this version of EIP-2333

    // https://github.com/ethereum/EIPs/blob/bf6288335ca92787c2efcdb26449f5be46ef6341/EIPS/eip-2333.md

    test('Test Case 1', () {
      var sk = HdKeys.keyGen(
          '3141592653589793238462643383279502884197169399375105820974944592'
              .hexToBytes());
      //36167147331491996618072159372207345412841461318189449162487002442599770291484
      expect(
          sk.toBytes().toHexString(),
          equals(
              '4ff5e145590ed7b71e577bb04032396d1619ff41cb4e350053ed2dce8d1efd1c'));
    });

    test('Test Case 2', () {
      var sk = HdKeys.keyGen(
          '0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00'
              .hexToBytes());
      //13904094584487173309420026178174172335998687531503061311232927109397516192843
      expect(
          sk.toBytes().toHexString(),
          equals(
              '1ebd704b86732c3f05f30563dee6189838e73998ebc9c209ccff422adee10c4b'));
    });

    test('Test Case 3', () {
      var sk = HdKeys.keyGen(
          'd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3'
              .hexToBytes());
      //44010626067374404458092393860968061149521094673473131545188652121635313364506
      expect(
          sk.toBytes().toHexString(),
          equals(
              '614d21b10c0e4996ac0608e0e7452d5720d95d20fe03c59a3321000a42432e1a'));
    });

    test('Test Case 4', () {
      var sk = HdKeys.keyGen(
          'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'
              .hexToBytes());
      //5399117110774477986698372024995405256382522670366369834617409486544348441851
      expect(
          sk.toBytes().toHexString(),
          equals(
              '0befcabff4a664461cc8f190cdd51c05621eb2837c71a1362df5b465a674ecfb'));

      var child = HdKeys.deriveChildSk(sk, 0);
      //11812940737387919040225825939013910852517748782307378293770044673328955938106
      expect(
          child.toBytes().toHexString(),
          equals(
              '1a1de3346883401f1e3b2281be5774080edb8e5ebe6f776b0f7af9fea942553a'));
    });
  });

  group('Field Tests', () {
    var a = Fq(BigInt.from(17), BigInt.from(30));
    var b = Fq(BigInt.from(17), BigInt.from(-18));
    var c = Fq2(BigInt.from(17), [a, b]);
    var d = Fq2(BigInt.from(17), [a + a, Fq(BigInt.from(17), BigInt.from(-5))]);
    var e = c * d;
    var f = e * d;
    var eSq = e * e;
    var eSqrt = (eSq as Fq2).modSqrt();

    var a2 = Fq(
      BigInt.parse('172487123095712930573140951348'),
      BigInt.parse(
          '3012492130751239573498573249085723940848571098237509182375'),
    );
    var b2 = Fq(BigInt.parse('172487123095712930573140951348'),
        BigInt.parse('3432984572394572309458723045723849'));
    var c2 = Fq2(BigInt.parse('172487123095712930573140951348'), [a2, b2]);
    test('Product of multiplying differing fields',
        () => expect(f, isNot(equals(e))));
    test(
        'Square then find root',
        () => expect(
              eSqrt.pow(BigInt.two),
              equals(eSq),
            ));
    test('Equality of differing fields', () => expect(b2, isNot(equals(c2))));

    var g = Fq6(BigInt.from(17), [c, d, d * d * c]);
    var h = Fq6(BigInt.from(17), [
      a + a * c,
      c * b * a,
      b * b * d * Fq(BigInt.from(17), BigInt.from(21))
    ]);
    var i = Fq12(BigInt.from(17), [g, h]);
    var x = Fq12(BigInt.from(17), [Fq6.zero(BigInt.from(17)), i.root]);

    test(
      'Inversions',
      () {
        expect(~(~i), equals(i));
        expect(~(i.root) * i.root, equals(Fq6.one(BigInt.from(17))));
        expect((~x) * x, equals(Fq12.one(BigInt.from(17))));
      },
    );

    var j = Fq6(BigInt.from(17),
        [a + a * c, Fq2.zero(BigInt.from(17)), Fq2.zero(BigInt.from(17))]);
    var j2 = Fq6(BigInt.from(17),
        [a + a * c, Fq2.zero(BigInt.from(17)), Fq2.one(BigInt.from(17))]);

    test(
      'Equality',
      () {
        expect(j, equals((a + a * c)));
        expect(j2, isNot(equals((a + a * c))));
        expect(j, isNot(equals(j2)));
      },
    );

    test(
      'Frob Coeffs',
      () {
        var one = Fq(defaultEc.q, BigInt.one);
        var two = one + one;
        var a = Fq2(defaultEc.q, [two, two]);
        var b = Fq6(defaultEc.q, [a, a, a]);
        var c = Fq12(defaultEc.q, [b, b]);
        for (var base in [a, b, c]) {
          for (int expo = 1; expo < base.extension; expo++) {
            expect(base.qiPow(expo), equals(base.pow(defaultEc.q.pow(expo))));
          }
        }
      },
    );
  });

  group('Ellipctic Curve', () {
    var q = defaultEc.q;
    var g = G1Generator();
    var g2 = G2Generator();

    test('G1 tests', () {
      expect(g.isOnCurve(), isTrue);
      expect(g * BigInt.two, equals(g + g));
      expect(g * BigInt.from(3), equals(g + g + g));
      expect((g * BigInt.from(3)).isOnCurve(), isTrue);
    });

    test('G2 tests', () {
      expect(g2.x * (Fq(q, BigInt.two) * g2.y),
          equals(Fq(q, BigInt.two) * (g2.x * g2.y)));
      expect(g2.isOnCurve(), isTrue);
      var s = g2 + g2;
      expect(untwist(twist(s.toAffine())), equals(s.toAffine()));
      expect(untwist(twist(s.toAffine()) * BigInt.from(5)),
          equals((s * BigInt.from(5)).toAffine()));
      expect(twist(s.toAffine() * BigInt.from(5)),
          equals(twist((s * BigInt.from(5)).toAffine())));
      expect(s.isOnCurve(), isTrue);
      expect(g2.isOnCurve(), isTrue);
      expect(g2 + g2, equals(g2 * BigInt.two));
      expect(g2 * BigInt.from(5),
          equals((g2 * BigInt.two) + (g2 * BigInt.two) + g2));
      var y = yForX(g2.x, defaultEcTwist);
      expect(y == g2.y || -y == g2.y, isTrue);

      var gJ = G1Generator(),
          g2J = G2Generator(),
          g2J2 = G2Generator() * BigInt.two;
      expect(g.toAffine().toJacobian(), equals(g));
      expect((gJ * BigInt.two).toAffine(), equals(g.toAffine() * BigInt.two));
      expect((g2J + g2J2).toAffine(), equals(g2.toAffine() * BigInt.from(3)));
    });
  });

  group('Test edge case sign FQ2', () {
    var q = defaultEc.q;
    var a = Fq(q, BigInt.from(62323));
    var testCase1 = Fq2(q, [a, Fq(q, BigInt.zero)]);
    var testCase2 = Fq2(q, [-a, Fq(q, BigInt.zero)]);
    test('Edge case 1', () => expect(testCase1, isNot(equals(testCase2))));
    var testCase3 = Fq2(q, [Fq(q, BigInt.zero), a]);
    var testCase4 = Fq2(q, [Fq(q, BigInt.zero), -a]);
    test('Edge case 2', () => expect(testCase3, isNot(equals(testCase4))));
  });
}
