import 'dart:typed_data';

import 'package:chia_bls_dart/src/bls/curve/ec.dart';
import 'package:chia_bls_dart/src/bls/curve/jacobian_point.dart';
import 'package:chia_bls_dart/src/bls/fields.dart';
import 'package:chia_bls_dart/src/bls/op_swu_g2.dart';
import 'package:chia_bls_dart/src/bls/pairing.dart';

import 'hd_keys.dart';
import 'private_key.dart';
import 'extensions/byte_conversion.dart';

const basicSchemeMPLCSID = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_';
const augSchemeMPLCSID = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_';
const popSchemeMPLCSID = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';
const popSchemeMPLPopCSID = 'BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';

abstract class CoreMPL {
  final String _cipherSuiteId;

  CoreMPL(String csId) : _cipherSuiteId = csId;

  PrivateKey keyGen(Uint8List seed) => HdKeys.keyGen(seed);

  Uint8List skToPk(PrivateKey secKey) => secKey.getG1().toBytes();

  JacobianPoint skToG1(PrivateKey secKey) => secKey.getG1();

  JacobianPoint sign(PrivateKey secKey, Uint8List message) =>
      g2Map(message, _cipherSuiteId.utf8ToBytes()) * secKey.value;

  PrivateKey deriveChildSk(PrivateKey sk, int index) =>
      HdKeys.deriveChildSk(sk, index);

  PrivateKey deriveChildSkUnhardened(PrivateKey sk, int index) =>
      HdKeys.deriveChildSkUnhardened(sk, index);

  JacobianPoint deriveChildPkUnhardened(JacobianPoint pk, int index) =>
      HdKeys.deriveChildG1Unhardened(pk, index);

  bool verify(
      JacobianPoint pubKey, Uint8List message, JacobianPoint signature) {
    try {
      signature.checkValid();
      pubKey.checkValid();
    } on AssertionError {
      return false;
    }

    var q = g2Map(message, _cipherSuiteId.utf8ToBytes());
    var one = Fq12.one(defaultEc.q);
    var pairingResult =
        atePairingMulti([pubKey, -G1Generator()], [q, signature], null);
    return pairingResult == one;
  }

  JacobianPoint aggregateSignatures(List<JacobianPoint> signatures) {
    if (signatures.isEmpty) {
      throw ArgumentError('Must aggregate at least 1 signature');
    }
    var aggregate = signatures[0];
    aggregate.checkValid();
    for (var signature in signatures.sublist(1)) {
      signature.checkValid();
      aggregate += signature;
    }
    return aggregate;
  }

  bool aggregateVerify(
    List<JacobianPoint> pubKeys,
    List<Uint8List> messages,
    JacobianPoint signature,
  ) {
    if (pubKeys.length != messages.length || pubKeys.isEmpty) {
      return false;
    }
    try {
      signature.checkValid();
      var qs = [signature];
      var ps = [-G1Generator()];
      for (int i = 0; i < pubKeys.length; i++) {
        pubKeys[i].checkValid();
        qs.add(g2Map(messages[i], _cipherSuiteId.utf8ToBytes()));
        ps.add(pubKeys[i]);
      }
      return Fq12.one(defaultEc.q) == atePairingMulti(ps, qs, null);
    } on AssertionError {
      return false;
    }
  }
}
