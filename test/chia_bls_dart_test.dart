import 'dart:math';
import 'dart:typed_data';

import 'package:chia_bls_dart/src/bls/curve/ec.dart';
import 'package:chia_bls_dart/src/bls/extensions/byte_conversion.dart';
import 'package:chia_bls_dart/src/bls/fields.dart';
import 'package:chia_bls_dart/src/bls/hash_to_field.dart';
import 'package:chia_bls_dart/src/bls/hd_keys.dart';
import 'package:chia_bls_dart/src/bls/hkdf.dart';
import 'package:chia_bls_dart/src/bls/op_swu_g2.dart';
import 'package:chia_bls_dart/src/bls/pairing.dart';
import 'package:chia_bls_dart/src/bls/private_key.dart';
import 'package:chia_bls_dart/src/bls/scheme.dart';
import 'package:crypto/crypto.dart';
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

  group('Test xmd', () {
    var msg = List.generate(48, (index) => Random.secure().nextInt(255));
    var dst = List.generate(16, (index) => Random.secure().nextInt(255));
    var ress = {};
    for (int l = 16; l <= 8192; l++) {
      var result = expandMessageXmd(msg, dst, l, sha512);
      test('of 8192 - check length', () => expect(l, equals(result.length)));
      var key = result.sublist(0, 16);
      ress[key] = (ress[key] ?? 0) + 1;
    }
    test('check all = 1', () => ress.values.every((element) => element == 1));
  });

  group('Test swu', () {
    var dst1 =
        'QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_'.utf8ToBytes();
    var msg1 = 'abcdef0123456789'.utf8ToBytes();
    var res = g2Map(msg1, dst1).toAffine();
    test(
        'test case 1',
        () => expect(
            ((res.x as Fq2).fields[0] as Fq).value,
            equals(BigInt.parse(
                '0x121982811D2491FDE9BA7ED31EF9CA474F0E1501297F68C298E9F4C0028ADD35AEA8BB83D53C08CFC007C1E005723CD0'))));
    test(
        'test case 2',
        () => expect(
            ((res.x as Fq2).fields[1] as Fq).value,
            equals(BigInt.parse(
                '0x190D119345B94FBD15497BCBA94ECF7DB2CBFD1E1FE7DA034D26CBBA169FB3968288B3FAFB265F9EBD380512A71C3F2C'))));
    test(
        'test case 3',
        () => expect(
            ((res.y as Fq2).fields[0] as Fq).value,
            equals(BigInt.parse(
                '0x05571A0F8D3C08D094576981F4A3B8EDA0A8E771FCDCC8ECCEAF1356A6ACF17574518ACB506E435B639353C2E14827C8'))));
    test(
        'test case 4',
        () => expect(
            ((res.y as Fq2).fields[1] as Fq).value,
            equals(BigInt.parse(
                '0x0BB5E7572275C567462D91807DE765611490205A941A5A6AF3B1691BFE596C31225D3AABDF15FAFF860CB4EF17C7C3BE'))));
  });

  group('Test Elements', () {
    var i1 = [1, 2].toBigInt();
    var i2 = [3, 1, 4, 1, 5, 9].toBigInt();
    var b1 = i1;
    var b2 = i2;
    var g1 = G1Generator();
    var g2 = G2Generator();
    var u1 = G1Infinity();
    var u2 = G2Infinity();

    var x1 = g1 * b1;
    var x2 = g1 * b2;
    var y1 = g2 * b1;
    var y2 = g2 * b2;

    var left = x1 + u1;
    var right = x1;
    test('G1', () {
      expect(x1, isNot(equals(x2)));
      expect(x1 * b1, equals(x1 * b1));
      expect(x1 * b1, isNot(equals(x1 * b2)));
      expect(left, equals(right));
      expect(x1 + x2, equals(x2 + x1));
      expect(x1 + -x1, equals(u1));
      expect(x1, equals(G1FromBytes(x1.toBytes())));
      var copy = x1.clone();
      expect(x1, equals(copy));
      x1 += x2;
      expect(x1, isNot(equals(copy)));
    });

    test('G2', () {
      expect(y1, isNot(equals(y2)));
      expect(y1 * b1, equals(y1 * b1));
      expect(y1 * b1, isNot(equals(y1 * b2)));
      expect(y1 + u2, equals(y1));
      expect(y1 + y2, equals(y2 + y1));
      expect(y1 + -y1, equals(u2));
      expect(y1, equals(G2FromBytes(y1.toBytes())));
      var copy = y1.clone();
      expect(y1, equals(copy));
      y1 += y2;
      expect(y1, isNot(equals(copy)));
    });

    x1 += x2;
    y1 += y2;

    test('Pairing operation', () {
      var pair = atePairing(x1, y1, defaultEc);
      expect(pair, isNot(equals(atePairing(x1, y2, defaultEc))));
      expect(pair, isNot(equals(atePairing(x2, y1, defaultEc))));
      var copy = pair.clone();
      expect(pair, equals(copy));
      var sk = BigInt.parse('728934712938472938472398074');
      var pk = g1 * sk;
      var Hm =
          y2 * BigInt.from(12371928312) + y2 * BigInt.from(12903812903891023);

      var sig = Hm * sk;

      expect(atePairing(g1, sig, defaultEc),
          equals(atePairing(pk, Hm, defaultEc)));
    });
  });

  group('Chia Test Vectors', () {
    test('Chia test vectors 1 (Basic)', () {
      var seed1 = Uint8List.fromList(List.filled(32, 0x00));
      var seed2 = Uint8List.fromList(List.filled(32, 0x01));
      var msg1 = Uint8List.fromList([7, 8, 9]);
      var msg2 = Uint8List.fromList([10, 11, 12]);
      var sk1 = BasicSchemeMPL().keyGen(seed1);
      var sk2 = BasicSchemeMPL().keyGen(seed2);

      expect(
          sk1.toBytes().toHexString(),
          equals(
              '4a353be3dac091a0a7e640620372f5e1e2e4401717c1e79cac6ffba8f6905604'));
      expect(
          sk1.getG1().toBytes().toHexString(),
          equals(
              '85695fcbc06cc4c4c9451f4dce21cbf8de3e5a13bf48f44cdbb18e2038ba7b8bb1632d7911ef1e2e08749bddbf165352'));

      var sig1 = BasicSchemeMPL().sign(sk1, msg1);
      var sig2 = BasicSchemeMPL().sign(sk2, msg2);

      expect(
          sig1.toBytes().toHexString(),
          equals(
              'b8faa6d6a3881c9fdbad803b170d70ca5cbf1e6ba5a586262df368c75acd1d1ffa3ab6ee21c71f844494659878f5eb230c958dd576b08b8564aad2ee0992e85a1e565f299cd53a285de729937f70dc176a1f01432129bb2b94d3d5031f8065a1'));
      expect(
          sig2.toBytes().toHexString(),
          equals(
              'a9c4d3e689b82c7ec7e838dac2380cb014f9a08f6cd6ba044c263746e39a8f7a60ffee4afb78f146c2e421360784d58f0029491e3bd8ab84f0011d258471ba4e87059de295d9aba845c044ee83f6cf2411efd379ef38bf4cf41d5f3c0ae1205d'));

      var aggSig1 = BasicSchemeMPL().aggregateSignatures([sig1, sig2]);
      expect(
          aggSig1.toBytes().toHexString(),
          equals(
              "aee003c8cdaf3531b6b0ca354031b0819f7586b5846796615aee8108fec75ef838d181f9d24"
              "4a94d195d7b0231d4afcf06f27f0cc4d3c72162545c240de7d5034a7ef3a2a03c0159de982fb"
              "c2e7790aeb455e27beae91d64e077c70b5506dea3"));
      expect(
          BasicSchemeMPL().aggregateVerify(
              [sk1.getG1(), sk2.getG1()], [msg1, msg2], aggSig1),
          isTrue);

      var msg3 = Uint8List.fromList([1, 2, 3]);
      var msg4 = Uint8List.fromList([1, 2, 3, 4]);
      var msg5 = Uint8List.fromList([1, 2]);

      var sig3 = BasicSchemeMPL().sign(sk1, msg3);
      var sig4 = BasicSchemeMPL().sign(sk1, msg4);
      var sig5 = BasicSchemeMPL().sign(sk2, msg5);

      var aggSig2 = BasicSchemeMPL().aggregateSignatures([sig3, sig4, sig5]);

      expect(
          BasicSchemeMPL().aggregateVerify(
              [sk1.getG1(), sk1.getG1(), sk2.getG1()],
              [msg3, msg4, msg5],
              aggSig2),
          isTrue);

      expect(
          aggSig2.toBytes().toHexString(),
          equals(
              "a0b1378d518bea4d1100adbc7bdbc4ff64f2c219ed6395cd36fe5d2aa44a4b8e710b607afd9"
              "65e505a5ac3283291b75413d09478ab4b5cfbafbeea366de2d0c0bcf61deddaa521f6020460f"
              "d547ab37659ae207968b545727beba0a3c5572b9c"));
    });

    test('Chia test vectors 2 (Augmented, aggregate of aggregates)', () {
      var msg1 = Uint8List.fromList([1, 2, 3, 40]);
      var msg2 = Uint8List.fromList([5, 6, 70, 201]);
      var msg3 = Uint8List.fromList([9, 10, 11, 12, 13]);
      var msg4 = Uint8List.fromList([15, 63, 244, 92, 0, 1]);

      var seed1 = Uint8List.fromList(List.filled(32, 0x02));
      var seed2 = Uint8List.fromList(List.filled(32, 0x03));

      var sk1 = AugSchemeMPL().keyGen(seed1);
      var sk2 = AugSchemeMPL().keyGen(seed2);

      var pk1 = sk1.getG1();
      var pk2 = sk2.getG1();

      var sig1 = AugSchemeMPL().sign(sk1, msg1);
      var sig2 = AugSchemeMPL().sign(sk2, msg2);
      var sig3 = AugSchemeMPL().sign(sk2, msg1);
      var sig4 = AugSchemeMPL().sign(sk1, msg3);
      var sig5 = AugSchemeMPL().sign(sk1, msg1);
      var sig6 = AugSchemeMPL().sign(sk1, msg4);

      var aggSigL = AugSchemeMPL().aggregateSignatures([sig1, sig2]);
      var aggSigR = AugSchemeMPL().aggregateSignatures([sig3, sig4, sig5]);
      var aggSig = AugSchemeMPL().aggregateSignatures([aggSigL, aggSigR, sig6]);

      expect(
          AugSchemeMPL().aggregateVerify([pk1, pk2, pk2, pk1, pk1, pk1],
              [msg1, msg2, msg1, msg3, msg1, msg4], aggSig),
          isTrue);

      expect(
          aggSig.toBytes().toHexString(),
          equals(
              "a1d5360dcb418d33b29b90b912b4accde535cf0e52caf467a005dc632d9f7af44b6c4e9acd4"
              "6eac218b28cdb07a3e3bc087df1cd1e3213aa4e11322a3ff3847bbba0b2fd19ddc25ca964871"
              "997b9bceeab37a4c2565876da19382ea32a962200"));
    });

    test('Chia test vectors 3 (PoP)', () {
      Uint8List seed1 = Uint8List.fromList(List.filled(32, 0x04));
      var sk1 = PopSchemeMPL().keyGen(seed1);
      var proof = PopSchemeMPL().popProve(sk1);
      expect(
          proof.toBytes().toHexString(),
          equals(
              "84f709159435f0dc73b3e8bf6c78d85282d19231555a8ee3b6e2573aaf66872d9203fefa1ef"
              "700e34e7c3f3fb28210100558c6871c53f1ef6055b9f06b0d1abe22ad584ad3b957f3018a8f5"
              "8227c6c716b1e15791459850f2289168fa0cf9115"));
    });
  });

  group('IETF test vectors', () {
    test('Pyecc vector', () {
      var refSig1Basic =
          '96ba34fac33c7f129d602a0bc8a3d43f9abc014eceaab7359146b4b150e57b808645738f35671e9e10e0d862a30cab70074eb5831d13e6a5b162d01eebe687d0164adbd0a864370a7c222a2768d7704da254f1bf1823665bc2361f9dd8c00e99';
      var refSig2Basic =
          'a402790932130f766af11ba716536683d8c4cfa51947e4f9081fedd692d6dc0cac5b904bee5ea6e25569e36d7be4ca59069a96e34b7f700758b716f9494aaa59a96e74d14a3b552a9a6bc129e717195b9d6006fd6d5cef4768c022e0f7316abf';
      var refSigABasic =
          '987cfd3bcd62280287027483f29c55245ed831f51dd6bd999a6ff1a1f1f1f0b647778b0167359c71505558a76e158e66181ee5125905a642246b01e7fa5ee53d68a4fe9bfb29a8e26601f0b9ad577ddd18876a73317c216ea61f430414ec51c5';
      var refSig1Aug =
          '8180f02ccb72e922b152fcedbe0e1d195210354f70703658e8e08cbebf11d4970eab6ac3ccf715f3fb876df9a9797abd0c1af61aaeadc92c2cfe5c0a56c146cc8c3f7151a073cf5f16df38246724c4aed73ff30ef5daa6aacaed1a26ecaa336b';
      var refSig2Aug =
          '99111eeafb412da61e4c37d3e806c6fd6ac9f3870e54da9222ba4e494822c5b7656731fa7a645934d04b559e9261b86201bbee57055250a459a2da10e51f9c1a6941297ffc5d970a557236d0bdeb7cf8ff18800b08633871a0f0a7ea42f47480';
      var refSigAAug =
          '8c5d03f9dae77e19a5945a06a214836edb8e03b851525d84b9de6440e68fc0ca7303eeed390d863c9b55a8cf6d59140a01b58847881eb5af67734d44b2555646c6616c39ab88d253299acc1eb1b19ddb9bfcbe76e28addf671d116c052bb1847';
      var refSig1Pop =
          '9550fb4e7f7e8cc4a90be8560ab5a798b0b23000b6a54a2117520210f986f3f281b376f259c0b78062d1eb3192b3d9bb049f59ecc1b03a7049eb665e0df36494ae4cb5f1136ccaeefc9958cb30c3333d3d43f07148c386299a7b1bfc0dc5cf7c';
      var refSig2Pop =
          'a69036bc11ae5efcbf6180afe39addde7e27731ec40257bfdc3c37f17b8df68306a34ebd10e9e32a35253750df5c87c2142f8207e8d5654712b4e554f585fb6846ff3804e429a9f8a1b4c56b75d0869ed67580d789870babe2c7c8a9d51e7b2a';
      var refSigAPop =
          'a4ea742bcdc1553e9ca4e560be7e5e6c6efa6a64dddf9ca3bb2854233d85a6aac1b76ec7d103db4e33148b82af9923db05934a6ece9a7101cd8a9d47ce27978056b0f5900021818c45698afdd6cf8a6b6f7fee1f0b43716f55e413d4b87a6039';

      var secret1 = Uint8List.fromList(List.filled(32, 0x01));
      var secret2 =
          Uint8List.fromList(List.generate(32, (x) => x * 314159 % 256));

      var sk1 = PrivateKey.fromBytes(secret1);
      var sk2 = PrivateKey.fromBytes(secret2);

      var msg = Uint8List.fromList(([3, 1, 4, 1, 5, 9]));
      var sig1Basic = BasicSchemeMPL().sign(sk1, msg);
      var sig2Basic = BasicSchemeMPL().sign(sk2, msg);
      var sigABasic =
          BasicSchemeMPL().aggregateSignatures([sig1Basic, sig2Basic]);
      var sig1Aug = AugSchemeMPL().sign(sk1, msg);
      var sig2Aug = AugSchemeMPL().sign(sk2, msg);
      var sigAAug = AugSchemeMPL().aggregateSignatures([sig1Aug, sig2Aug]);
      var sig1Pop = PopSchemeMPL().sign(sk1, msg);
      var sig2Pop = PopSchemeMPL().sign(sk2, msg);
      var sigAPop = PopSchemeMPL().aggregateSignatures([sig1Pop, sig2Pop]);

      expect(sig1Basic.toBytes().toHexString(), equals(refSig1Basic));
      expect(sig2Basic.toBytes().toHexString(), equals(refSig2Basic));
      expect(sigABasic.toBytes().toHexString(), equals(refSigABasic));
      expect(sig1Aug.toBytes().toHexString(), equals(refSig1Aug));
      expect(sig2Aug.toBytes().toHexString(), equals(refSig2Aug));
      expect(sigAAug.toBytes().toHexString(), equals(refSigAAug));
      expect(sig1Pop.toBytes().toHexString(), equals(refSig1Pop));
      expect(sig2Pop.toBytes().toHexString(), equals(refSig2Pop));
      expect(sigAPop.toBytes().toHexString(), equals(refSigAPop));
    });
  });
}
