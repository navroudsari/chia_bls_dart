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

class CoreMPL {
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

class BasicSchemeMPL extends CoreMPL {
  BasicSchemeMPL() : super(basicSchemeMPLCSID);

  @override
  bool aggregateVerify(
    List<JacobianPoint> pubKeys,
    List<Uint8List> messages,
    JacobianPoint signature,
  ) {
    if ((pubKeys.length != messages.length) || pubKeys.isEmpty) {
      return false;
    }
    if (Set.from(messages).length != messages.length) {
      // Disallow repeated messages
      return false;
    }
    return super.aggregateVerify(pubKeys, messages, signature);
  }
}

class AugSchemeMPL extends CoreMPL {
  AugSchemeMPL() : super(augSchemeMPLCSID);

  @override
  JacobianPoint sign(PrivateKey secKey, Uint8List message) {
    return _signPrependPk(secKey, message, secKey.getG1());
  }

  JacobianPoint _signPrependPk(
      PrivateKey secKey, Uint8List message, JacobianPoint prependPk) {
    var ppk = prependPk.toBytes();
    var augMessage = Uint8List(ppk.length + message.length);

    for (int i = 0; i < ppk.length; i++) {
      augMessage[i] = ppk[i];
    }
    for (int i = 0; i < message.length; i++) {
      augMessage[ppk.length + i] = message[i];
    }

    return super.sign(secKey, augMessage);
  }

  @override
  bool verify(
      JacobianPoint pubKey, Uint8List message, JacobianPoint signature) {
    var ppk = pubKey.toBytes();
    var augMessage = Uint8List(ppk.length + message.length);

    for (int i = 0; i < ppk.length; i++) {
      augMessage[i] = ppk[i];
    }
    for (int i = 0; i < message.length; i++) {
      augMessage[ppk.length + i] = message[i];
    }
    return super.verify(pubKey, augMessage, signature);
  }

  @override
  bool aggregateVerify(
    List<JacobianPoint> pubKeys,
    List<Uint8List> messages,
    JacobianPoint signature,
  ) {
    if ((pubKeys.length != messages.length) || pubKeys.isEmpty) {
      return false;
    }

    List<Uint8List> mPrimes = [];
    for (int i = 0; i < pubKeys.length; i++) {
      mPrimes.add(Uint8List.fromList(pubKeys[i].toBytes() + messages[i]));
    }
    return super.aggregateVerify(pubKeys, mPrimes, signature);
  }
}

class PopSchemeMPL extends CoreMPL {
  PopSchemeMPL() : super(popSchemeMPLCSID);

  JacobianPoint popProve(PrivateKey secKey) {
    var pubKey = secKey.getG1();
    return g2Map(pubKey.toBytes(), popSchemeMPLPopCSID.utf8ToBytes()) *
        secKey.value;
  }

  bool popVerify(JacobianPoint pubKey, JacobianPoint proof) {
    try {
      proof.checkValid();
      pubKey.checkValid();
      var q = g2Map(pubKey.toBytes(), popSchemeMPLPopCSID.utf8ToBytes());
      var one = Fq12.one(defaultEc.q);
      var pairingResult =
          atePairingMulti([pubKey, -G1Generator()], [q, proof], defaultEc);
      return pairingResult == one;
    } on AssertionError {
      return false;
    }
  }

  bool fastAggregateVerify(
      List<JacobianPoint> pubKeys, Uint8List message, JacobianPoint signature) {
    if (pubKeys.isEmpty) return false;
    JacobianPoint aggregate = pubKeys[0];
    for (var pubKey in pubKeys.sublist(1)) {
      aggregate += pubKey;
    }
    return super.verify(aggregate, message, signature);
  }
}
