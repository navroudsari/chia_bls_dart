import 'dart:math' as math;
import 'dart:typed_data';

import 'package:quiver/iterables.dart';

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

yForX(Field x, EC? ec) {
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

JacobianPoint doublePointJacobian(JacobianPoint p1, bool isExtension, EC? ec) {
  /// Jacobian elliptic curve point doubling, see
  /// http://www.hyperelliptic.org/EFD/oldefd/jacobian.html

  ec ??= defaultEc;

  var X = p1.x, Y = p1.y, Z = p1.z;
  if (Y == (isExtension ? Fq2.zero(ec.q) : Fq.zero(ec.q)) || p1.infinity) {
    return isExtension
        ? JacobianPoint(Fq2.one(ec.q), Fq2.one(ec.q), Fq2.zero(ec.q), false, ec)
        : JacobianPoint(Fq.one(ec.q), Fq.one(ec.q), Fq.zero(ec.q), false, ec);
  }

  // # S = 4*X*Y^2
  var S = Fq(ec.q, BigInt.from(4)) * X * Y * Y;

  var Z_sq = Z * Z;
  var Z_4th = Z_sq * Z_sq;
  var Y_sq = Y * Y;
  var Y_4th = Y_sq * Y_sq;

  // # M = 3*X^2 + a*Z^4
  var M = Fq(ec.q, BigInt.from(3)) * X * X;
  M += ec.a * Z_4th;

  // # X' = M^2 - 2*S
  var X_p = M * M - Fq(ec.q, BigInt.two) * S;
  // # Y' = M*(S - X') - 8*Y^4
  var Y_p = M * (S - X_p) - Fq(ec.q, BigInt.from(8)) * Y_4th;
  // # Z' = 2*Y*Z
  var Z_p = Fq(ec.q, BigInt.two) * Y * Z;
  return JacobianPoint(X_p, Y_p, Z_p, false, ec);
}

JacobianPoint addPointsJacobian(
    JacobianPoint p1, JacobianPoint p2, bool isExtension, EC? ec) {
  // Jacobian elliptic curve point addition, see
  // http://www.hyperelliptic.org/EFD/oldefd/jacobian.html

  ec ??= defaultEc;

  if (p1.infinity) return p2;
  if (p2.infinity) return p1;
  // # U1 = X1*Z2^2
  var U1 = p1.x * (p2.z.pow(BigInt.two));
  // # U2 = X2*Z1^2
  var U2 = p2.x * (p1.z.pow(BigInt.two));
  // # S1 = Y1*Z2^3
  var S1 = p1.y * (p2.z.pow(BigInt.from(3)));
  // # S2 = Y2*Z1^3
  var S2 = p2.y * (p1.z.pow(BigInt.from(3)));
  if (U1 == U2) {
    if (S1 != S2) {
      return isExtension
          ? JacobianPoint(
              Fq2.one(ec.q), Fq2.one(ec.q), Fq2.zero(ec.q), true, ec)
          : JacobianPoint(Fq.one(ec.q), Fq.one(ec.q), Fq.zero(ec.q), true, ec);
    } else {
      return doublePointJacobian(p1, isExtension, ec);
    }
  }

  // # H = U2 - U1
  var H = U2 - U1;
  // # R = S2 - S1
  var R = S2 - S1;
  var H_sq = H * H;
  var H_cu = H * H_sq;
  // # X3 = R^2 - H^3 - 2*U1*H^2
  var X3 = R * R - H_cu - Fq(ec.q, BigInt.two) * U1 * H_sq;
  // # Y3 = R*(U1*H^2 - X3) - S1*H^3
  var Y3 = R * (U1 * H_sq - X3) - S1 * H_cu;
  // # Z3 = H*Z1*Z2
  var Z3 = H * p1.z * p2.z;
  return JacobianPoint(X3, Y3, Z3, false, ec);
}

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
  if (p1.infinity || c % ec.q == BigInt.zero) {
    return JacobianPoint(Fq.one(ec.q), Fq.one(ec.q), Fq.zero(ec.q), true, ec);
  }

  var result =
      JacobianPoint(Fq.one(ec.q), Fq.one(ec.q), Fq.zero(ec.q), true, ec);
  var addend = p1;
  while (c > BigInt.zero) {
    if ((c & BigInt.one) != BigInt.zero) {
      result += addend;
    }
    //double point
    addend += addend;
    c = c >> 1;
  }
  return result;
}

bool signFq(Fq element, EC? ec) {
  ec ??= defaultEc;
  return element > Fq(ec.q, ((ec.q - BigInt.one) ~/ BigInt.two));
}

bool signFq2(Fq2 element, EC? ec) {
  ec ??= defaultEcTwist;
  if (element.fields[1] == Fq(ec.q, BigInt.zero)) {
    return signFq(element.fields[0] as Fq, ec);
  }

  return element.fields[1] > Fq(ec.q, ((ec.q - BigInt.one) ~/ BigInt.two));
}

JacobianPoint G1Generator({EC? ec}) {
  ec ??= defaultEc;
  return AffinePoint(ec.gx, ec.gy, false, ec).toJacobian();
}

JacobianPoint G2Generator({EC? ec}) {
  ec ??= defaultEcTwist;
  return AffinePoint(ec.g2x, ec.g2y, false, ec).toJacobian();
}

JacobianPoint G1Infinity({EC? ec}) {
  ec ??= defaultEc;
  return JacobianPoint(Fq.one(ec.q), Fq.one(ec.q), Fq.one(ec.q), true, ec);
}

JacobianPoint G2Infinity({EC? ec}) {
  ec ??= defaultEc;
  return JacobianPoint(Fq2.one(ec.q), Fq2.one(ec.q), Fq2.one(ec.q), true, ec);
}

JacobianPoint G1FromBytes(Uint8List bytes, EC? ec) {
  ec ??= defaultEc;
  return bytesToPoint(bytes, false, ec);
}

JacobianPoint G2FromBytes(Uint8List bytes, EC? ec) {
  ec ??= defaultEc;
  return bytesToPoint(bytes, true, ec);
}

Uint8List pointToBytes(JacobianPoint pointJ, bool isExtension, EC? ec) {
  ec ??= defaultEc;
  var point = pointJ.toAffine();
  var output = point.x.toBytes();

  // # If the y coordinate is the bigger one of the two, set the first
  // # bit to 1.
  if (point.infinity) {
    return (Uint8List.fromList([0x40] + List.filled(output.length - 1, 0)));
  }

  bool sign;
  if (isExtension) {
    sign = signFq2(point.y as Fq2, ec);
  } else {
    sign = signFq(point.y as Fq, ec);
  }

  if (sign) {
    output[0] |= 0xA0;
  } else {
    output[0] |= 0x80;
  }
  return output;
}

JacobianPoint bytesToPoint(Uint8List buffer, bool isExtension, EC? ec) {
  //  Zcash serialization described in https://datatracker.ietf.org/doc/draft-irtf-cfrg-pairing-friendly-curves/

  ec ??= defaultEc;

  if (!isExtension) {
    if (buffer.length != 48) {
      throw AssertionError("G1Elements must be 48 bytes");
    }
  } else {
    if (buffer.length != 96) {
      throw AssertionError("G2Elements must be 96 bytes");
    }
  }

  var mByte = buffer[0] & 0xE0;

  if ([0x20, 0x60, 0xE0].contains(mByte)) {
    throw AssertionError("Invalid first three bits");
  }

  var CBit = mByte & 0x80; // First bit
  var IBit = mByte & 0x40; // Second bit
  var SBit = mByte & 0x20; // Third bit

  if (CBit == 0) {
    throw AssertionError("First bit must be 1 (only compressed points)");
  }

  buffer = Uint8List.fromList(([buffer[0] & 0x1F]) + buffer.sublist(1));

  if (IBit == 1) {
    if (buffer.any((e) => e != 0)) {
      throw AssertionError("Point at infinity set, but data not all zeroes");
    }

    return isExtension
        ? AffinePoint(Fq.zero(ec.q), Fq.zero(ec.q), true, ec).toJacobian()
        : AffinePoint(Fq2.zero(ec.q), Fq2.zero(ec.q), true, ec).toJacobian();
  }

  var x =
      isExtension ? Fq.fromBytes(buffer, ec.q) : Fq2.fromBytes(buffer, ec.q);
  var yValue = yForX(x, ec);
  var signFn = isExtension == false ? signFq : signFq2;

  var y = signFn(yValue, ec) == (SBit != 0) ? yValue : -yValue;

  return AffinePoint(x, y, false, ec).toJacobian();
}

AffinePoint untwist(AffinePoint point, {EC? ec}) {
  // Given a point on G2 on the twisted curve, this converts its
  // coordinates back from Fq2 to Fq12. See Craig Costello book, look
  // up twists.

  ec ??= defaultEc;
  var f = Fq12.one(ec.q);
  var wsq = Fq12(ec.q, [f.root, Fq6.zero(ec.q)]);
  var wcu = Fq12(ec.q, [Fq6.zero(ec.q), f.root]);
  var newX = point.x * wsq;
  var newY = point.y * wcu;
  return AffinePoint(newX, newY, false, ec);
}

AffinePoint twist(AffinePoint point, {EC? ec}) {
  // Given an untwisted point, this converts it's
  // coordinates to a point on the twisted curve. See Craig Costello
  // book, look up twists.

  ec ??= defaultEcTwist;
  var f = Fq12.one(ec.q);
  var wsq = Fq12(ec.q, [f.root, Fq6.zero(ec.q)]);
  var wcu = Fq12(ec.q, [Fq6.zero(ec.q), f.root]);
  var newX = point.x / wsq;
  var newY = point.y / wcu;
  return AffinePoint(newX, newY, false, ec);
}

//  Isogeny map evaluation specified by map_coeffs

//  map_coeffs should be specified as (xnum, xden, ynum, yden)

//  This function evaluates the isogeny over Jacobian projective coordinates.
//  For details, see Section 4.3 of
//     Wahby and Boneh, "Fast and simple constant-time hashing to the BLS12-381 elliptic curve."
//     ePrint # 2019/403, https://ia.cr/2019/403.
JacobianPoint evalIso(JacobianPoint P, List<List<Fq2>> mapCoeffs, EC ec) {
  var x = P.x, y = P.y, z = P.z;
  List<Fq2?> mapVals = List.filled(4, null);

  // Precompute the required powers of Z^2
  int maxord = mapCoeffs.fold(
      0, (int prevValue, List<Fq2> item) => math.max(prevValue, item.length));

  List<Fq2?> zPows = List.filled(maxord, null);
  zPows[0] = z.pow(BigInt.zero) as Fq2; //# type: ignore
  zPows[1] = z.pow(BigInt.two) as Fq2; //# type: ignore
  for (var idx in range(2, zPows.length)) {
    assert(zPows[idx.toInt() - 1] != null);
    assert(zPows[1] != null);
    zPows[idx.toInt()] = (zPows[idx.toInt() - 1] as Fq2) * zPows[1] as Fq2;
  }

  // Compute the numerator and denominator of the X and Y maps via Horner's rule

  for (var i in enumerate(mapCoeffs)) {
    var coeffsZ =
        zip([i.value.reversed.toList(), zPows.sublist(0, i.value.length)])
            .map((zPowC) {
      return (zPowC[0] as Fq2) * (zPowC[1] as Fq2);
    }).toList();

    var tmp = coeffsZ[0];
    for (var coeff in coeffsZ.sublist(1, coeffsZ.length)) {
      tmp = tmp * x as Fq2;
      tmp = tmp + coeff as Fq2;
    }
    mapVals[i.index] = tmp as Fq2;
  }

  // xden is of order 1 less than xnum, so one needs to multiply it by an extra factor of Z^2
  assert(mapCoeffs[1].length + 1 == mapCoeffs[0].length);
  assert(zPows[1] != null);
  assert(mapVals[1] != null);
  mapVals[1] = mapVals[1]! * zPows[1] as Fq2;
  // Multiply the result of Y map by the y-coordinate y / z^3
  assert(mapVals[2] != null);
  assert(mapVals[3] != null);
  mapVals[2] = mapVals[2]! * y as Fq2;
  mapVals[3] = mapVals[3]! * (z.pow(BigInt.from(3))) as Fq2;

  var Z = mapVals[1]! * mapVals[3];
  var X = mapVals[0]! * mapVals[3] * Z;
  var Y = mapVals[2]! * mapVals[1] * Z * Z;
  return JacobianPoint(X, Y, Z, P.infinity, ec);
}
