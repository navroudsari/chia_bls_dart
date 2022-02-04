import 'dart:typed_data';

import 'package:chia_bls_dart/src/bls/curve/ec.dart';
import 'package:chia_bls_dart/src/bls/curve/jacobian_point.dart';
import 'package:chia_bls_dart/src/bls/hd_keys.dart';
import 'extensions/byte_conversion.dart';

class PrivateKey {
  final BigInt value;

  PrivateKey(this.value) : assert(value < defaultEc.n);

  int get size => 32;

  static PrivateKey fromBytes(Uint8List bytes) {
    return PrivateKey(bytes.toBigInt() % defaultEc.n);
  }

  static PrivateKey fromSeed(Uint8List seed) {
    return HdKeys.keyGen(seed);
  }

  static PrivateKey fromInt(BigInt n) {
    return PrivateKey(n % defaultEc.n);
  }

  static aggregate(List<PrivateKey> privateKeys) =>
      // Aggregates private keys together
      PrivateKey(privateKeys.fold(
              BigInt.zero,
              (BigInt previousValue, PrivateKey element) =>
                  previousValue + element.value) %
          defaultEc.n);

  Uint8List toBytes() {
    return value.toBytes();
  }

  JacobianPoint getG1() {
    return G1Generator() * value;
  }

  @override
  bool operator ==(other) {
    if (other is! PrivateKey) {
      return false;
    }
    return value == other.value;
  }

  @override
  int get hashCode => value.toInt();

  @override
  String toString() => 'PrivateKey($value)';
}
