import 'dart:typed_data';

import 'curve/affine_point.dart';
import 'curve/ec.dart';
import 'curve/jacobian_point.dart';
import 'fields.dart';

Uint8List intToBits(BigInt i) {
  if (i < BigInt.one) return Uint8List.fromList([0]);
  List<int> bits = [];
  while (i != BigInt.zero) {
    bits.add((i % BigInt.two).toInt());
    i = i ~/ BigInt.two;
  }
  return Uint8List.fromList(bits.reversed.toList());
}

Field doubleLineEval(AffinePoint R, AffinePoint P, EC? ec) {
  // Creates an equation for a line tangent to R,
  // and evaluates this at the point P. f(x) = y - sv - v.
  // f(P).

  ec ??= defaultEc;

  var R12 = untwist(R);

  var slope = (Fq(ec.q, BigInt.from(3)) * R12.x.pow(BigInt.two) + ec.a) /
      (Fq(ec.q, BigInt.two) * R12.y);
  var v = R12.y - slope * R12.x;

  return P.y - P.x * slope - v;
}

Field addLineEval(AffinePoint R, AffinePoint Q, AffinePoint P, EC? ec) {
  // Creates an equation for a line between R and Q,
  // and evaluates this at the point P. f(x) = y - sv - v.
  // f(P).
  ec ??= defaultEc;

  var R12 = untwist(R);
  var Q12 = untwist(Q);

  // This is the case of a vertical line, where the denominator
  //  will be 0.
  if (R12 == -Q12) {
    return P.x - R12.x as Fq;
  }

  var slope = (Q12.y - R12.y) / (Q12.x - R12.x);
  var v = (Q12.y * R12.x - R12.y * Q12.x) / (R12.x - Q12.x);

  return P.y - P.x * slope - v;
}

Fq12 millerLoop(BigInt T, AffinePoint P, AffinePoint Q, EC? ec) {
  // Performs a double and add algorithm for the ate pairing. This algorithm
  // is taken from Craig Costello's "Pairing for Beginners".

  ec ??= defaultEc;

  var TBits = intToBits(T);
  var R = Q;
  var f = Fq12.one(ec.q); //# f is an element of Fq12
  for (var i = 1; i < TBits.length; i++) {
    // # Compute sloped line lrr
    var lrr = doubleLineEval(R, P, ec);
    f = f * f * lrr as Fq12;

    R = R * Fq(ec.q, BigInt.two);
    if (TBits[i] == 1) {
      // # Compute sloped line lrq
      var lrq = addLineEval(R, Q, P, ec);
      f = f * lrq as Fq12;

      R = R + Q;
    }
  }
  return f;
}

Fq12 finalExponentiation(Fq12 element, EC? ec) {
  // Performs a final exponentiation to map the result of the Miller
  // loop to a unique element of Fq12.

  ec ??= defaultEc;

  if (ec.k == 12) {
    var ans = element.pow((ec.q.pow(4) - ec.q.pow(2) + BigInt.one) ~/ ec.n);
    ans = ans.qiPow(2) * ans;
    ans = ans.qiPow(6) / ans;
    return ans as Fq12;
  } else {
    return element.pow(((ec.q.pow(ec.k) - BigInt.one) ~/ ec.n)) as Fq12;
  }
}

Fq12 atePairing(JacobianPoint P, JacobianPoint Q, EC? ec) {
  // Performs one ate pairing.

  ec ??= defaultEc;

  var t = defaultEc.x + BigInt.one;
  var T = (t - BigInt.one).abs();
  var element = millerLoop(T, P.toAffine(), Q.toAffine(), ec);
  return finalExponentiation(element, ec);
}

Fq12 atePairingMulti(List<JacobianPoint> Ps, List<JacobianPoint> Qs, EC? ec) {
  // Computes multiple pairings at once. This is more efficient,
  // since we can multiply all the results of the miller loops,
  // and perform just one final exponentiation.

  ec ??= defaultEc;

  var t = defaultEc.x + BigInt.one;
  var T = (t - BigInt.one).abs();
  var prod = Fq12.one(ec.q);
  for (int i = 0; i < Qs.length; i++) {
    prod = prod * millerLoop(T, Ps[i].toAffine(), Qs[i].toAffine(), ec) as Fq12;
  }
  return finalExponentiation(prod, ec);
}
