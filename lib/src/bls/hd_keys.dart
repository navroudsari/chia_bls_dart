import 'dart:math';
import 'dart:typed_data';
import 'package:chia_bls_dart/src/bls/curve/ec.dart';
import 'package:chia_bls_dart/src/bls/curve/jacobian_point.dart';
import 'package:chia_bls_dart/src/bls/extensions/byte_conversion.dart';
import 'package:crypto/crypto.dart';

import 'hash_to_field.dart';
import 'hkdf.dart';
import 'private_key.dart';

class HdKeys {
  static const hashLength = 32;

  static PrivateKey keyGen(Uint8List seed) {
    int L = 48;

    var okm = HKDF256.extractExpand(L, Uint8List.fromList(seed + [0]),
        'BLS-SIG-KEYGEN-SALT-'.utf8ToBytes(), Uint8List.fromList([0, L]));
    return PrivateKey(os2ip(okm) % defaultEc.n);
  }

  static Uint8List ikmToLamportSK(Uint8List ikm, Uint8List salt) =>
      HKDF256.extractExpand(hashLength * 255, ikm, salt, Uint8List(0));

  static Uint8List parentSkToLamportPK(PrivateKey parentSK, int index) {
    if (index < 0 || index >= pow(2, 32)) {
      throw AssertionError("Expected index to be uint32");
    }

    final salt = index.asUint32Bytes();
    final ikm = parentSK.toBytes();
    final notIkm = Uint8List.fromList(ikm.map((byte) => ~byte).toList());
    final lamport0 = ikmToLamportSK(ikm, salt);
    final lamport1 = ikmToLamportSK(notIkm, salt);

    //concat hashes
    final List<int> lamportPk = [];

    for (int i = 0; i < 255; i++) {
      lamportPk.addAll(sha256
          .convert(List.from(
              lamport0.sublist(i * hashLength, i * hashLength + hashLength)))
          .bytes);
    }

    for (int i = 0; i < 255; i++) {
      lamportPk.addAll(sha256
          .convert(List.from(
              lamport1.sublist(i * hashLength, i * hashLength + hashLength)))
          .bytes);
    }

    return Uint8List.fromList(sha256.convert(lamportPk).bytes);
  }

  static PrivateKey deriveChildSk(PrivateKey parentSk, int index) {
    // Derives a hardened EIP-2333 child private key, from a parent private key,
    // at the specified index.
    if (index < 0 || index >= pow(2, 32)) {
      throw Exception("Expected index to be uint32");
    }

    var lamportPk = parentSkToLamportPK(parentSk, index);
    var child = keyGen(lamportPk);
    return child;
  }

  static PrivateKey deriveChildSkUnhardened(PrivateKey parentSk, int index) {
    if (index < 0 || index >= pow(2, 32)) {
      throw Exception("Expected index to be uint32");
    }

    var g1 = parentSk.getG1().toBytes() + index.asUint32Bytes();
    var digest = Uint8List.fromList(sha256.convert(g1).bytes);

    return PrivateKey.aggregate([PrivateKey.fromBytes(digest), parentSk]);
  }

  static JacobianPoint deriveChildG1Unhardened(JacobianPoint pk, int index) {
    // Derives an unhardened BIP-32 child public key, from a parent public key,
    // at the specified index. WARNING: this key is not as secure as a hardened key.

    if (index < 0 || index >= pow(2, 32)) {
      throw Exception("Expected index to be uint32");
    }

    Uint8List buffer = pk.toBytes() + index.asUint32Bytes() as Uint8List;

    return pk + (G1Generator() * PrivateKey.fromBytes(buffer).value);
  }

  static JacobianPoint deriveChildG2Unhardened(JacobianPoint pk, int index) {
    // Derives an unhardened BIP-32 child public key, from a parent public key,
    // at the specified index. WARNING: this key is not as secure as a hardened key.

    if (index < 0 || index >= pow(2, 32)) {
      throw Exception("Expected uint32");
    }

    Uint8List buffer = pk.toBytes() + index.asUint32Bytes() as Uint8List;

    return pk + (G2Generator() * PrivateKey.fromBytes(buffer));
  }
}
