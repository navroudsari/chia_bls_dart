import 'package:chia_bls_dart/src/bls/curve/jacobian_point.dart';
import 'package:quiver/core.dart';

import '../fields.dart';
import 'ec.dart';

class AffinePoint {
  // Elliptic curve point, can represent any curve, and use Fq or Fq2
  //   coordinates.

  final bool isExtension;
  final Field x;
  final Field y;
  final bool infinity;
  final EC ec;

  AffinePoint(this.x, this.y, this.infinity, EC? ec)
      : ec = ec ?? defaultEc,
        isExtension = x is FieldExtBase {
    if ((x is! Fq && x is! FieldExtBase) ||
        ((y is! Fq && y is! FieldExtBase)) ||
        x.runtimeType != y.runtimeType) {
      throw ArgumentError('x,y should be the field elements');
    }
  }

  bool isOnCurve() {
    // Check that y^2 = x^3 + ax + b.
    if (infinity) return true;
    var left = y * y, right = x * x * x + ec.a * x + ec.b;
    return left == right;
  }

  JacobianPoint toJacobian() {
    return JacobianPoint(x, y, Fq.one(ec.q), infinity, ec);
  }

  AffinePoint operator +(AffinePoint other) {
    if (other is! AffinePoint) throw ArgumentError('Incorrect object');
    return addPoints(this, other);
  }

  AffinePoint operator -() => AffinePoint(x, -y, infinity, ec);
  AffinePoint operator -(AffinePoint other) => this + -other;

  AffinePoint operator *(other) {
    if (other is! BigInt && other is! Fq) {
      throw ArgumentError('Error, must be BigInt or Fq');
    }
    return scalarMultJacobian(other, toJacobian(), ec).toAffine();
  }

  @override
  bool operator ==(other) {
    if (other is! AffinePoint) {
      return false;
    }
    return (x == other.x && y == other.y && infinity == other.infinity);
  }

  @override
  int get hashCode => hash3(x, y, infinity);

  @override
  String toString() =>
      'AffinePoint(x=${x.toString()}, y=${y.toString()}, i=${infinity.toString()})';

  AffinePoint negate() {
    return AffinePoint(x, -y, infinity, ec);
  }
}
