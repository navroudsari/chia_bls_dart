import 'dart:typed_data';

import 'package:chia_bls_dart/src/bls/curve/ec.dart';
import 'package:chia_bls_dart/src/bls/curve/jacobian_point.dart';
import 'package:chia_bls_dart/src/bls/hash_to_field.dart';
import 'extensions/byte_conversion.dart';

import 'hkdf.dart';

class PrivateKey {
  final BigInt _value;

  PrivateKey(BigInt value)
      : assert(value < defaultEc.n),
        _value = value;

  int get size => 32;

  static PrivateKey fromBytes(Uint8List bytes) {
    return PrivateKey(bytes.toBigInt() % defaultEc.n);
  }

  static PrivateKey fromSeed(Uint8List seed) {
    int L = 48;
    seed.add(0);
    var okm = HKDF256.extractExpand(L, seed,
        'BLS-SIG-KEYGEN-SALT-'.utf8ToBytes(), Uint8List.fromList([0, L]));
    return PrivateKey(os2ip(okm) % defaultEc.n);
  }

  static PrivateKey fromInt(BigInt n) {
    return PrivateKey(n % defaultEc.n);
  }

  static aggregate(List<PrivateKey> privateKeys) =>
      // Aggregates private keys together
      PrivateKey(privateKeys.fold(
              BigInt.zero,
              (BigInt previousValue, PrivateKey element) =>
                  previousValue + element._value) %
          defaultEc.n);

  Uint8List toBytes() {
    return _value.toBytes();
  }

  JacobianPoint getG1() {
    return G1Generator() * _value;
  }

  @override
  bool operator ==(other) {
    if (other is! PrivateKey) {
      return false;
    }
    return _value == other._value;
  }

  @override
  int get hashCode => _value.toInt();

  @override
  String toString() => 'PrivateKey($_value)';
}
