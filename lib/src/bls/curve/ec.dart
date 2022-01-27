import '../fields.dart';
import '../bls12381.dart';
import 'affine_point.dart';
import 'jacobian_point.dart';

var defaultEc = EC(q, a, b, gx, gy, g2x, g2y, n, h, x, k, sqrtN3, sqrtN3m1o2);
var defaultEcTwist =
    EC(q, aTwist, bTwist, gx, gy, g2x, g2y, n, hEff, x, k, sqrtN3, sqrtN3m1o2);

class EC {
  final BigInt q;
  final Field a;
  final Field b;
  final Fq gx;
  final Fq gy;
  final Fq2 g2x;
  final Fq2 g2y;
  final BigInt n;
  final BigInt h;
  final BigInt x;
  final int k;
  final BigInt sqrtN3;
  final BigInt sqrtN3m1o2;

  const EC(this.q, this.a, this.b, this.gx, this.gy, this.g2x, this.g2y, this.n,
      this.h, this.x, this.k, this.sqrtN3, this.sqrtN3m1o2);
}

yForX(Field x, {EC? ec}) {
  //Solves y = sqrt(x^3 + ax + b) for both valid ys.
  ec ??= defaultEc;
  var u = x * x * x + ec.a * x + ec.b;
  var y = (u as dynamic).modSqrt();
  if (y == BigInt.zero || !AffinePoint(x, y, false, ec).isOnCurve()) {
    throw ArgumentError("No y for point x");
  }
  return y;
}

AffinePoint doublePoint(AffinePoint p1, {EC? ec}) {
  // Basic elliptic curve point doubling
  ec ??= defaultEc;
  var x = p1.x, y = p1.y;
  var left = Fq(ec.q, BigInt.from(3)) * x * x;
  left = left + ec.a;
  var s = left / (Fq(ec.q, BigInt.two) * y);
  var newX = s * s - x - x;
  var newY = s * (x - newX) - y;
  return AffinePoint(newX, newY, false, ec);
}

AffinePoint addPoints(AffinePoint p1, AffinePoint p2, {EC? ec}) {
  //Basic elliptic curve point addition.
  ec ??= defaultEc;
  assert(p1.isOnCurve());
  assert(p2.isOnCurve());
  if (p1.infinity) return p2;
  if (p2.infinity) return p1;
  if (p1 == p2) return doublePoint(p1, ec: ec);
  if (p1.x == p2.x) {
    return AffinePoint(Fq.zero(ec.q), Fq.zero(ec.q), true, ec);
  }

  var x1 = p1.x, y1 = p1.y;
  var x2 = p2.x, y2 = p2.y;
  var s = (y2 - y1) / (x2 - x1);
  var newX = s * s - x1 - x2;
  var newY = s * (x1 - newX) - y1;
  return AffinePoint(newX, newY, false, ec);
}

// JacobianPoint double_point_jacobian(p1: JacobianPoint, ec=default_ec, FE=Fq) -> JacobianPoint:

//     /// Jacobian elliptic curve point doubling, see
//     /// http://www.hyperelliptic.org/EFD/oldefd/jacobian.html

//     X, Y, Z = p1.x, p1.y, p1.z
//     if Y == FE.zero(ec.q) or p1.infinity:
//         return JacobianPoint(FE.one(ec.q), FE.one(ec.q), FE.zero(ec.q), True, ec)

//     # S = 4*X*Y^2
//     S = Fq(ec.q, 4) * X * Y * Y

//     Z_sq = Z * Z
//     Z_4th = Z_sq * Z_sq
//     Y_sq = Y * Y
//     Y_4th = Y_sq * Y_sq

//     # M = 3*X^2 + a*Z^4
//     M = Fq(ec.q, 3) * X * X
//     M += ec.a * Z_4th

//     # X' = M^2 - 2*S
//     X_p = M * M - Fq(ec.q, 2) * S
//     # Y' = M*(S - X') - 8*Y^4
//     Y_p = M * (S - X_p) - Fq(ec.q, 8) * Y_4th
//     # Z' = 2*Y*Z
//     Z_p = Fq(ec.q, 2) * Y * Z
//     return JacobianPoint(X_p, Y_p, Z_p, False, ec)

// def add_points_jacobian(
//     p1: JacobianPoint, p2: JacobianPoint, ec=default_ec, FE=Fq
// ) -> JacobianPoint:
//     """
//     Jacobian elliptic curve point addition, see
//     http://www.hyperelliptic.org/EFD/oldefd/jacobian.html
//     """
//     if p1.infinity:
//         return p2
//     if p2.infinity:
//         return p1
//     # U1 = X1*Z2^2
//     U1 = p1.x * (p2.z ** 2)
//     # U2 = X2*Z1^2
//     U2 = p2.x * (p1.z ** 2)
//     # S1 = Y1*Z2^3
//     S1 = p1.y * (p2.z ** 3)
//     # S2 = Y2*Z1^3
//     S2 = p2.y * (p1.z ** 3)
//     if U1 == U2:
//         if S1 != S2:
//             return JacobianPoint(FE.one(ec.q), FE.one(ec.q), FE.zero(ec.q), True, ec)
//         else:
//             return double_point_jacobian(p1, ec, FE)

//     # H = U2 - U1
//     H = U2 - U1
//     # R = S2 - S1
//     R = S2 - S1
//     H_sq = H * H
//     H_cu = H * H_sq
//     # X3 = R^2 - H^3 - 2*U1*H^2
//     X3 = R * R - H_cu - Fq(ec.q, 2) * U1 * H_sq
//     # Y3 = R*(U1*H^2 - X3) - S1*H^3
//     Y3 = R * (U1 * H_sq - X3) - S1 * H_cu
//     # Z3 = H*Z1*Z2
//     Z3 = H * p1.z * p2.z
//     return JacobianPoint(X3, Y3, Z3, False, ec)

// def scalar_mult(c, p1: AffinePoint, ec=default_ec, FE=Fq) -> AffinePoint:
//     """
//     Double and add, see
//     https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
//     """
//     if p1.infinity or c % ec.q == 0:
//         return AffinePoint(FE.zero(ec.q), FE.zero(ec.q), ec)
//     result = AffinePoint(FE.zero(ec.q), FE.zero(ec.q), True, ec)
//     addend = p1
//     while c > 0:
//         if c & 1:
//             result += addend

//         # double point
//         addend += addend
//         c = c >> 1

//     return result

JacobianPoint scalarMultJacobian(c, JacobianPoint p1, EC? ec) {
  // Double and add, see
  // https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication

  ec ??= defaultEc;

  if (c is Fq) {
    c = c.value;
  }
  if (p1.infinity || c % ec.q == 0) {
    return JacobianPoint(Fq.one(ec.q), Fq.one(ec.q), Fq.zero(ec.q), true, ec);
  }

  var result =
      JacobianPoint(Fq.one(ec.q), Fq.one(ec.q), Fq.zero(ec.q), true, ec);
  var addend = p1;
  while (c > 0) {
    if (c & 1) {
      result += addend;
    }
    //double point
    addend += addend;
    c = c >> 1;
  }
  return result;
}
