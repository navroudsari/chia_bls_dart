import 'package:chia_bls_dart/src/bls/curve/affine_point.dart';

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

  AffinePoint toAffine() {
    if (infinity) {
      return AffinePoint(Fq.zero(ec.q), Fq.zero(ec.q), infinity, ec);
    }
    var newX = x / (z.pow(BigInt.two));
    var newY = y / (z.pow(BigInt.from(3)));
    return AffinePoint(newX, newY, infinity, ec);
  }

  JacobianPoint operator +(JacobianPoint other) {
    if (other.infinity) {
      return this;
    } else if (infinity) {
      return other;
    }

    return addPointsJacobian(this, other, isExtension, ec);
  }
}
