import 'dart:typed_data';

/// Finite Field
abstract class Field implements FieldOperators {
  abstract BigInt Q;
  abstract int extension;

  Field fromBytes(Uint8List bytes, BigInt Q);
  Field pow(BigInt exp);
  Field qiPow(int i);
  Field modSqrt();
  Field clone();

  one(BigInt Q);
  zero(BigInt Q);
  fromFq(BigInt Q, Fq fq);

  @override
  bool operator ==(other);
  @override
  int get hashCode;
  @override
  String toString();
}

abstract class FieldOperators {
  Field operator +(other);
  Field operator -(other);
  Field operator *(other);
  Field operator ~/(other); //floordiv
  Field operator /(other);
  Field operator -();
  Field operator ~(); //invert
  bool operator <(other);
  bool operator >(other);
  bool operator >=(other);
  bool operator <=(other);
}

abstract class FieldExtBase implements Field {
  abstract Field root;
  abstract int embedding;
  abstract Field baseField;
  @override
  abstract BigInt Q;
  @override
  abstract int extension;
}

class Fq implements Field {
  @override
  int extension = 1;

  @override
  BigInt Q;

  BigInt value;

  Fq(this.Q, BigInt value) : value = value % Q;

  factory Fq.zero(BigInt Q) => Fq(Q, BigInt.zero);

  factory Fq.one(BigInt Q) => Fq(Q, BigInt.one);

  factory Fq.from(BigInt Q, Fq fq) => fq;

  @override
  Fq operator *(other) {
    if ((other is! Fq)) {
      throw UnimplementedError();
    }
    return Fq(Q, value * other.value);
  }

  @override
  Fq operator +(other) {
    if (other is! Fq) {
      throw UnimplementedError();
    }
    return Fq(Q, value + other.value);
  }

  @override
  Fq operator -() {
    return Fq(Q, -value);
  }

  @override
  Fq operator -(other) {
    if (other is! Fq) {
      throw UnimplementedError();
    }
    return Fq(Q, value - other.value);
  }

  @override
  Fq operator ~() {
    BigInt x0 = BigInt.one, x1 = BigInt.zero, y0 = BigInt.one, y1 = BigInt.one;
    BigInt a = Q, b = value, q;

    while (a != BigInt.zero) {
      q = b ~/ a;
      b = a;
      a = b % a;
      x0 = x1;
      x1 = x0 - q * x1;
      y0 = y1;
      y1 = y0 - q * y1;
    }

    return Fq(Q, x0);
  }

  @override
  Fq operator ~/(other) {
    if (other is BigInt && other is! Fq) {
      other = Fq(Q, other);
    }
    return this * ~other;
  }

  @override
  Fq operator /(other) => this ~/ other;

  @override
  bool operator <(other) {
    if (other is! Fq) {
      throw UnimplementedError();
    }
    return value < other.value;
  }

  @override
  bool operator <=(other) {
    if (other is! Fq) {
      throw UnimplementedError();
    }
    return value <= other.value;
  }

  @override
  bool operator >(other) {
    if (other is! Fq) {
      throw UnimplementedError();
    }
    return value > other.value;
  }

  @override
  bool operator >=(other) {
    if (other is! Fq) {
      throw UnimplementedError();
    }
    return value >= other.value;
  }

  @override
  Fq clone() {
    // TODO: implement clone
    throw UnimplementedError();
  }

  @override
  Fq fromBytes(Uint8List bytes, BigInt q) {
    // TODO: implement fromBytes
    throw UnimplementedError();
  }

  @override
  Fq pow(BigInt exp) {
    // TODO: implement pow
    throw UnimplementedError();
  }

  @override
  Fq qiPow(int i) {
    // TODO: implement qiPow
    throw UnimplementedError();
  }

  @override
  fromFq(BigInt Q, Fq fq) {
    // TODO: implement fromFq
    throw UnimplementedError();
  }

  @override
  one(BigInt Q) {
    // TODO: implement one
    throw UnimplementedError();
  }

  @override
  zero(BigInt Q) {
    // TODO: implement zero
    throw UnimplementedError();
  }

  @override
  Field modSqrt() {
    if (value.compareTo(BigInt.zero) == 0) {
      return Fq(Q, BigInt.zero);
    }
    if (value.modPow((Q - BigInt.one) ~/ BigInt.from(2), Q) != BigInt.one) {
      throw Exception("No sqrt exists");
    }
    if (Q % BigInt.from(4) == BigInt.from(3)) {
      return Fq(Q, value.modPow((Q + BigInt.one) ~/ BigInt.from(4), Q));
    }
    if (Q % BigInt.from(8) == BigInt.from(5)) {
      return Fq(Q, value.modPow((Q + BigInt.from(3)) ~/ BigInt.from(8), Q));
    }

    var S = BigInt.zero;
    var q = Q - BigInt.one;

    while (q % BigInt.two == BigInt.zero) {
      q = q ~/ BigInt.two;
      S += BigInt.one;
    }

    var z = BigInt.zero;

    for (BigInt i = BigInt.zero; i.compareTo(S) < 0; i += BigInt.one) {
      var euler = i.modPow((Q - BigInt.one) ~/ BigInt.two, Q);
      if (euler == BigInt.from(-1) % Q) {
        z = i;
        break;
      }
    }

    var M = S;
    var c = z.modPow(q, Q);
    var t = value.modPow(q, Q);
    var R = value.modPow((q + BigInt.one) ~/ BigInt.from(2), Q);

    while (true) {
      if (t == BigInt.zero) {
        return Fq(Q, BigInt.zero);
      }
      if (t == BigInt.one) {
        return Fq(Q, R);
      }
      var i = BigInt.zero;
      var f = t;
      while (f.compareTo(BigInt.one) != 0) {
        f = f.modPow(BigInt.two, Q);
        i += BigInt.one;
      }
      var b = c.modPow(BigInt.two.modPow(M - i - BigInt.one, Q), Q);
      M = i;
      c = b.modPow(BigInt.two, Q);
      t = (t * c) % Q;
      R = (R * b) % Q;
    }
  }
}
