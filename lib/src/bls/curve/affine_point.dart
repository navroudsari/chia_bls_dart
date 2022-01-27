import 'package:chia_bls_dart/src/bls/curve/jacobian_point.dart';
import 'package:quiver/core.dart';

import '../fields.dart';
import 'ec.dart';

class AffinePoint {
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
    if (infinity) return true;

    var left = y * y, right = x * x * x + ec.a * x + ec.b;

    return left == right;
  }

  JacobianPoint toJacobian() {
    return JacobianPoint(x, y, Fq.one(ec.q), infinity, ec);
  }

  AffinePoint operator +(AffinePoint other) {
    if (other is! AffinePoint) throw ArgumentError('Incorrect object');

    assert(isOnCurve());
    assert(other.isOnCurve());

    if (infinity) return other;
    if (other.infinity) return this;
    if (this == other) doublePoint(this);

    var x1 = x, y1 = y;
    var x2 = other.x, y2 = other.y;

    var s = (y2 - y1) / (x2 - x1);
    var newX = s * s - x1 - x2;
    var newY = s * (x1 - newX) - y1;
    return AffinePoint(newX, newY, false, ec);
  }

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
