import 'dart:typed_data';

import 'package:chia_bls_dart/src/bls/curve/affine_point.dart';
import 'package:chia_bls_dart/src/bls/extensions/byte_conversion.dart';
import 'package:crypto/crypto.dart';
import 'package:quiver/core.dart';

import '../fields.dart';
import 'ec.dart';

class JacobianPoint {
  //  Elliptic curve point, can represent any curve, and use Fq or Fq2
  //   coordinates. Uses Jacobian coordinates so that point addition
  //   does not require slow inversion.

  final bool isExtension;
  final bool infinity;
  final Field x;
  final Field y;
  final Field z;
  final EC ec;

  JacobianPoint(this.x, this.y, this.z, this.infinity, EC? ec)
      : ec = ec ?? defaultEc,
        isExtension = x is! Fq {
    if ((x is! Fq) && (x is! FieldExtBase) ||
        ((y is! Fq) && (y is! FieldExtBase)) ||
        ((z is! Fq) && (z is! FieldExtBase))) {
      throw ArgumentError("x,y,z should be field elements");
    }
  }

  bool isOnCurve() {
    if (infinity) return true;
    return toAffine().isOnCurve();
  }

  AffinePoint toAffine() {
    if (infinity) {
      return AffinePoint(Fq.zero(ec.q), Fq.zero(ec.q), infinity, ec);
    }
    var newX = x / (z.pow(BigInt.two));
    var newY = y / (z.pow(BigInt.from(3)));
    return AffinePoint(newX, newY, infinity, ec);
  }

  void checkValid() {
    if (!(isOnCurve() && (this * ec.n == G2Infinity()))) {
      throw AssertionError("Point is not valid");
    }
  }

  BigInt getFingerprint() {
    Uint8List dig =
        Uint8List.fromList(sha256.convert(toBytes()).bytes.sublist(0, 4));
    return dig.toBigInt();
  }

  JacobianPoint operator +(JacobianPoint other) {
    return addPointsJacobian(this, other, isExtension, ec);
  }

  @override
  bool operator ==(other) {
    if (other is! JacobianPoint) {
      return false;
    }
    return toAffine() == other.toAffine();
  }

  JacobianPoint operator *(c) {
    if ((c is! BigInt) && (c is! Fq)) {
      throw ArgumentError("Error, must be Bigint or Fq");
    }
    return scalarMultJacobian(c, this, ec);
  }

  JacobianPoint operator -() => (-toAffine()).toJacobian();
  JacobianPoint operator -(JacobianPoint other) => throw UnimplementedError();

  Uint8List toBytes() => pointToBytes(this, isExtension, ec);

  @override
  int get hashCode => hash4(x, y, z, infinity);

  @override
  String toString() =>
      'AffinePoint(x=${x.toString()}, y=${y.toString()}, z=${z.toString()}, i=${infinity.toString()})';
}
