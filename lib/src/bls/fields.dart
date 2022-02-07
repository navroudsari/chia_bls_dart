import 'dart:typed_data';
import 'package:chia_bls_dart/src/bls/extensions/byte_conversion.dart';
import 'package:quiver/collection.dart';
import 'package:quiver/core.dart';
import 'package:quiver/iterables.dart';

import 'bls12381.dart';

/// Finite Field
abstract class Field implements FieldOperators {
  abstract BigInt Q;
  abstract int extension;

  Field _from(BigInt Q, Fq fq);
  Field _fromBytes(Uint8List bytes, BigInt Q);
  Field _zero(BigInt Q);
  Field _one(BigInt Q);
  Field _clone();

  Field pow(BigInt exp);
  Field qiPow(int i);
  bool toBool();
  Uint8List toBytes();

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
  Field operator ~/(other);
  Field operator /(other);
  Field operator -();
  Field operator ~();
  bool operator <(other);
  bool operator >(other);
  bool operator >=(other);
  bool operator <=(other);
}

abstract class FieldExtBase implements Field {
  abstract Field root;
  abstract int embedding;
  late Field baseField;

  @override
  BigInt Q;
  @override
  abstract int extension;

  final List<Field> fields;

  FieldExtBase(this.Q, this.fields) {
    if (fields.length != embedding) {
      throw ArgumentError("Invalid number of arguments, expected $embedding");
    }

    fields.any((child) => child.extension != (extension ~/ embedding))
        ? throw ArgumentError(
            "Invalid child extension, expected ${extension ~/ embedding}")
        : baseField = fields[0];
  }

  @override
  FieldExtBase _zero(BigInt Q) => _from(Q, Fq(Q, BigInt.zero));

  @override
  FieldExtBase _one(BigInt Q) => _from(Q, Fq(Q, BigInt.one));

  @override
  FieldExtBase _from(BigInt Q, Fq fq) {
    var y = baseField._from(Q, fq);
    var z = baseField._zero(Q);
    var ret = create(Q, range(embedding).map((i) => i == 0 ? y : z).toList());
    switch (runtimeType) {
      case Fq2:
        ret.root = Fq(Q, BigInt.from(-1));
        break;
      case Fq6:
        ret.root = Fq2(Q, [Fq.one(Q), Fq.one(Q)]);
        break;
      case Fq12:
        ret.root = Fq6(Q, [Fq2.zero(Q), Fq2.one(Q), Fq2.zero(Q)]);
        break;
      default:
        throw ArgumentError("Unsupported type");
    }
    return ret;
  }

  @override
  FieldExtBase _fromBytes(Uint8List bytes, BigInt Q) {
    assert(bytes.length == extension * 48);
    var embeddedSize = 48 * (extension ~/ embedding);
    List<List<int>> tup = [];
    for (int i = 0; i < embedding; i++) {
      tup.add(bytes.sublist(i * embeddedSize, (i + 1) * embeddedSize));
    }
    return create(
        Q,
        tup.reversed
            .map((buffer) => Fq.fromBytes(Uint8List.fromList(buffer), Q))
            .toList());
  }

  FieldExtBase create(BigInt Q, List<Field> fields);

  @override
  Uint8List toBytes() {
    var bytes = Uint8List(0);
    for (var field in fields.reversed) {
      bytes.addAll(field.toBytes());
    }

    return Uint8List.fromList(bytes);
  }

  @override
  bool toBool() => fields.any((element) => false);

  @override
  FieldExtBase _clone() {
    var ret = create(Q, fields.map((field) => field._clone()).toList());
    ret.root = root;
    return ret;
  }

  @override
  FieldExtBase pow(BigInt exp) {
    assert(exp >= BigInt.zero);
    var ans = _one(Q);
    var base = this;
    ans.root = root;

    while (exp != BigInt.zero) {
      if ((exp & BigInt.one) != BigInt.zero) {
        ans *= base;
      }
      base *= base;
      exp >>= 1;
    }

    return ans;
  }

  @override
  FieldExtBase qiPow(int i) {
    if (Q != q) throw UnimplementedError();
    i %= extension;
    if (i == 0) return this;

    List<Field> r = [];
    fields.asMap().forEach((j, a) {
      r.add(j == 0
          ? a.qiPow(i)
          : a.qiPow(i) *
              frobCoeffs.entries
                  .firstWhere((f) => f.key == "$extension$i$j")
                  .value);
    });

    var ret = create(Q, r);
    ret.root = root;
    return ret;
  }

  @override
  FieldExtBase operator +(other) {
    dynamic otherNew;
    if (other.runtimeType != runtimeType) {
      if (other is! BigInt && other.extension > extension) {
        throw UnimplementedError();
      }
      otherNew = fields.map((field) => baseField._zero(Q)).toList();
      otherNew[0] = otherNew[0] + other;
    } else {
      otherNew = other.fields;
    }

    var ret = create(
        Q,
        zip([fields, otherNew as List<Field>])
            .map((field) => field[0] + field[1])
            .toList());
    ret.root = root;
    return ret;
  }

  @override
  FieldExtBase operator -(other) => this + (-other);

  @override
  FieldExtBase operator *(other) {
    if (other is BigInt) {
      var ret = create(Q, fields.map((field) => field * other).toList());
      ret.Q = Q;
      ret.root = root;
      return ret;
    }
    if (extension < other.extension) {
      return other * this;
    }

    var buf = fields.map((field) => baseField._zero(Q)).toList();

    if (other is FieldExtBase) {
      for (var x in enumerate(fields)) {
        if (extension == other.extension) {
          for (var y in enumerate(other.fields)) {
            if (x.value.toBool() && y.value.toBool()) {
              if (x.index + y.index >= embedding) {
                buf[(x.index + y.index) % embedding] +=
                    x.value * y.value * root;
              } else {
                buf[(x.index + y.index) % embedding] += x.value * y.value;
              }
            }
          }
        } else {
          if (x.value.toBool()) {
            buf[x.index] = x.value * other;
          }
        }
      }
    }
    var ret = create(Q, buf);
    ret.root = root;
    return ret;
  }

  @override
  FieldExtBase operator ~/(other) => this * ~other;

  @override
  FieldExtBase operator /(other) => this ~/ other;

  @override
  FieldExtBase operator -() {
    var ret = create(Q, fields.map((field) => -field).toList());
    ret.root = root;
    return ret;
  }

  @override
  bool operator <(other) =>
      zip([fields.reversed as List<Field>, other.reversed as List<Field>])
          .any((f) => f[0] < f[1]);

  @override
  bool operator >(other) =>
      zip([fields, other as List<Field>]).any((f) => f[0] > f[1]);

  @override
  bool operator ==(other) {
    if (other.runtimeType != runtimeType) {
      if (other is FieldExtBase || other is BigInt) {
        if (other is! FieldExtBase || extension > other.extension) {
          for (int i = 1; i < embedding; i++) {
            if (fields[i] != root._zero(Q)) {
              return false;
            }
          }
          return fields[0] == other;
        }
        throw UnimplementedError();
      }
      // throw UnimplementedError();
      return other == this;
    } else if (other is FieldExtBase) {
      return listsEqual(fields, other.fields) && Q == other.Q;
    } else {
      throw UnimplementedError();
    }
  }

  @override
  int get hashCode => hash4(Q, extension, embedding, fields);

  @override
  String toString() => "Fq$extension(${fields.join(', ')}) )";
}

class Fq implements Field {
  @override
  int extension = 1;

  @override
  BigInt Q;

  BigInt value;

  Fq(this.Q, BigInt value) : value = value % Q;
  Fq._()
      : Q = BigInt.zero,
        value = BigInt.zero;

  factory Fq.from(BigInt Q, Fq fq) => fq;
  factory Fq.fromBytes(Uint8List bytes, BigInt Q) =>
      Fq._()._fromBytes(bytes, Q);
  factory Fq.zero(BigInt Q) => Fq._()._zero(Q);
  factory Fq.one(BigInt Q) => Fq._()._one(Q);

  @override
  Fq _zero(BigInt Q) => Fq(Q, BigInt.zero);

  @override
  Fq _one(BigInt Q) => Fq(Q, BigInt.one);

  @override
  Fq _from(BigInt Q, Fq fq) => fq;

  @override
  Fq _fromBytes(Uint8List bytes, BigInt Q) {
    assert(bytes.length == 48);
    return Fq(Q, bytes.toBigInt());
  }

  @override
  bool toBool() => true;

  @override
  bool operator ==(other) {
    if (other is! Fq) {
      return false;
    }
    return value == other.value && Q == other.Q;
  }

  @override
  int get hashCode => hash2(Q, value);
  @override
  String toString() {
    var s = value.toRadixString(16);
    var s2 = s.length > 10
        ? s.substring(0, 7) + "..." + s.substring(s.length - 5, s.length)
        : s;
    return "Fq(0x$s2)";
  }

  @override
  Field operator *(other) {
    if ((other is! Fq)) {
      return other * this;
      // throw UnimplementedError();
    }
    return Fq(Q, value * other.value);
  }

  @override
  Field operator +(other) {
    if (other is! Fq) {
      return other + this;
    }
    return Fq(Q, value + other.value);
  }

  @override
  Fq operator -() {
    return Fq(Q, -value);
  }

  @override
  Field operator -(other) {
    if (other is! Fq) {
      return other - this;
    }
    return Fq(Q, value - other.value);
  }

  @override
  Fq operator ~() {
    // Extended euclidian algorithm for inversion.
    var x0 = BigInt.one, x1 = BigInt.zero, y0 = BigInt.zero, y1 = BigInt.one;
    var a = Q, b = value;

    while (a != BigInt.zero) {
      var _b = b;
      var _x0 = x0;
      var _y0 = y0;
      // (q, b a)
      var q = b ~/ a;
      b = a;
      a = _b % a;
      // (x0, x1)
      x0 = x1;
      x1 = _x0 - q * x1;
      // (y0, y1)
      y0 = y1;
      y1 = _y0 - q * y1;
    }

    return Fq(Q, x0);
  }

  @override
  Field operator ~/(other) {
    if (other is BigInt && other is! Fq) {
      other = Fq(Q, other);
    }
    return this * ~other;
  }

  @override
  Field operator /(other) => this ~/ other;

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
  Fq _clone() => Fq(Q, value);

  @override
  Fq pow(BigInt other) {
    if (other == BigInt.zero) {
      return Fq(Q, BigInt.one);
    } else if (other == BigInt.one) {
      return Fq(Q, value);
    } else if ((other % BigInt.two) == BigInt.zero) {
      return Fq(Q, value * value).pow(other ~/ BigInt.two);
    } else {
      return Fq(Q, value * value).pow(other ~/ BigInt.two) * this as Fq;
    }
  }

  @override
  Fq qiPow(int i) => this;

  Fq modSqrt() {
    if (value == BigInt.zero) {
      return Fq(Q, BigInt.zero);
    }
    if (value.modPow((Q - BigInt.one) ~/ BigInt.two, Q) != BigInt.one) {
      throw StateError("No sqrt exists");
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

    for (var i = BigInt.zero; i < Q; i += BigInt.one) {
      var euler = i.modPow((Q - BigInt.one) ~/ BigInt.two, Q);
      if (euler == -BigInt.one % Q) {
        z = i;
        break;
      }
    }

    var M = S;
    var c = z.modPow(q, Q);
    var t = value.modPow(q, Q);
    var R = value.modPow((q + BigInt.one) ~/ BigInt.two, Q);

    while (true) {
      if (t == BigInt.zero) {
        return Fq(Q, BigInt.zero);
      }
      if (t == BigInt.one) {
        return Fq(Q, R);
      }
      var i = BigInt.zero;
      var f = t;
      while (f != BigInt.one) {
        f = f.pow(2) % Q;
        i += BigInt.one;
      }
      var b = c.modPow(BigInt.two.modPow(M - i - BigInt.one, Q), Q);
      M = i;
      c = b.pow(2) % Q;
      t = (t * c) % Q;
      R = (R * b) % Q;
    }
  }

  @override
  Uint8List toBytes() => value.toBytes();
}

class Fq2 extends FieldExtBase {
  @override
  Field root;
  @override
  int extension = 2;
  @override
  int embedding = 2;

  Fq2(Q, List<Field> fields)
      : root = Fq(Q, BigInt.from(-1)),
        super(Q, fields);

  Fq2._()
      : root = Fq._(),
        super(BigInt.zero, [Fq._(), Fq._()]);

  factory Fq2.zero(BigInt Q) => Fq2._()._from(Q, Fq.zero(Q)) as Fq2;
  factory Fq2.one(BigInt Q) => Fq2._()._from(Q, Fq.one(Q)) as Fq2;
  factory Fq2.fromBytes(Uint8List bytes, BigInt Q) =>
      Fq2._()._fromBytes(bytes, Q) as Fq2;

  @override
  Fq2 create(BigInt Q, List<Field> fields) => Fq2(Q, fields);

  @override
  bool operator <=(other) {
    throw UnimplementedError();
  }

  @override
  bool operator >=(other) {
    throw UnimplementedError();
  }

  @override
  Fq2 operator ~() {
    var a = fields[0], b = fields[1];
    var factor = ~(a * a + b * b);
    var ret = Fq2(Q, [a * factor, -b * factor]);
    return ret;
  }

  Fq2 mulByNonResidue() {
    var a = fields[0], b = fields[1];
    return Fq2(Q, [a - b, a + b]);
  }

  Fq2 modSqrt() {
    var a0 = fields[0], a1 = fields[1];
    if (a1 == baseField._zero(Q)) {
      return _from(Q, (a0 as Fq).modSqrt()) as Fq2;
    }
    var alpha, gamma, delta;
    alpha = a0.pow(BigInt.two) + a1.pow(BigInt.two);
    gamma = alpha.pow((Q - BigInt.one) ~/ BigInt.two);
    if (gamma == Fq(Q, -BigInt.one)) throw StateError("No sqrt exists");
    alpha = (alpha as Fq).modSqrt();
    delta = (a0 + alpha) * ~Fq(Q, BigInt.two);
    gamma = delta.pow((Q - BigInt.one) ~/ BigInt.two);
    if (gamma == Fq(Q, -BigInt.one)) {
      delta = (a0 - alpha) * ~Fq(Q, BigInt.two);
    }

    var x0, x1;
    x0 = (delta as Fq).modSqrt();
    x1 = a1 * ~(Fq(Q, BigInt.two) * x0);
    return Fq2(Q, [x0, x1]);
  }
}

class Fq6 extends FieldExtBase {
  @override
  Field root;
  @override
  int extension = 6;
  @override
  int embedding = 3;

  Fq6(Q, List<Field> fields)
      : root = Fq2(Q, [Fq.one(Q), Fq.one(Q)]),
        super(Q, fields);

  Fq6._()
      : root = Fq2._(),
        super(BigInt.zero, [Fq2._(), Fq2._(), Fq2._()]);

  factory Fq6.zero(BigInt Q) => Fq6._()._from(Q, Fq.zero(Q)) as Fq6;
  factory Fq6.one(BigInt Q) => Fq6._()._from(Q, Fq.one(Q)) as Fq6;
  factory Fq6.fromBytes(Uint8List bytes, BigInt Q) =>
      Fq6._()._fromBytes(bytes, Q) as Fq6;

  @override
  FieldExtBase create(BigInt Q, List<Field> fields) => Fq6(Q, fields);

  @override
  bool operator <=(other) => throw UnimplementedError();

  @override
  bool operator >=(other) => throw UnimplementedError();

  @override
  Fq6 operator ~() {
    var a = fields[0], b = fields[1], c = fields[2];
    var g0 = a * a - b * (c as Fq2).mulByNonResidue();
    var g1 = ((c * c) as Fq2).mulByNonResidue();
    var g2 = b * b - a * c;
    var factor = ~(g0 * a + ((g1 * c + g2 * b) as Fq2).mulByNonResidue());

    return Fq6(Q, [g0 * factor, g1 * factor, g2 * factor]);
  }

  Fq6 mulByNonResidue() {
    var a = fields[0], b = fields[1], c = fields[2];
    return Fq6(Q, [c * root, a, b]);
  }
}

class Fq12 extends FieldExtBase {
  @override
  Field root;
  @override
  int extension = 12;
  @override
  int embedding = 2;

  Fq12(Q, List<Field> fields)
      : root = Fq6(Q, [Fq2.zero(Q), Fq2.one(Q), Fq2.zero(Q)]),
        super(Q, fields);

  Fq12._()
      : root = Fq6._(),
        super(BigInt.zero, [Fq6._(), Fq6._()]);

  factory Fq12.zero(BigInt Q) => Fq12._()._from(Q, Fq.zero(Q)) as Fq12;
  factory Fq12.one(BigInt Q) => Fq12._()._from(Q, Fq.one(Q)) as Fq12;
  factory Fq12.fromBytes(Uint8List bytes, BigInt Q) =>
      Fq12._()._fromBytes(bytes, Q) as Fq12;

  @override
  FieldExtBase create(BigInt Q, List<Field> fields) => Fq12(Q, fields);

  @override
  bool operator <=(other) => throw UnimplementedError();

  @override
  bool operator >=(other) => throw UnimplementedError();

  @override
  Field operator ~() {
    var a = fields[0], b = fields[1];
    var factor = ~(a * a - (b * b as Fq6).mulByNonResidue());
    return Fq12(Q, [a * factor, -b * factor]);
  }
}

var rv1 = BigInt.parse(
  '0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09',
);

var rootsOfUnity = [
  Fq2(q, [Fq(q, BigInt.one), Fq(q, BigInt.zero)]),
  Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.one)]),
  Fq2(q, [Fq(q, rv1), Fq(q, rv1)]),
  Fq2(q, [Fq(q, rv1), Fq(q, (q - rv1))]),
];

var frobCoeffs = {
  "211": Fq(q, BigInt.from(-1)),
  "611": Fq2(q, [
    Fq(q, BigInt.zero),
    Fq(
      q,
      BigInt.parse(
          '0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC'),
    )
  ]),
  "612": Fq2(q, [
    Fq(
      q,
      BigInt.parse(
          '0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD'),
    ),
    Fq(q, BigInt.zero)
  ]),
  "621": Fq2(q, [
    Fq(
      q,
      BigInt.parse(
          '0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE'),
    ),
    Fq(q, BigInt.zero)
  ]),
  "622": Fq2(q, [
    Fq(
      q,
      BigInt.parse(
          '0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC'),
    ),
    Fq(q, BigInt.zero)
  ]),
  "631": Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.one)]),
  "632": Fq2(q, [
    Fq(
      q,
      BigInt.parse(
          '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA'),
    ),
    Fq(q, BigInt.zero)
  ]),
  "641": Fq2(q, [
    Fq(
      q,
      BigInt.parse(
          '0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC'),
    ),
    Fq(q, BigInt.zero)
  ]),
  "642": Fq2(q, [
    Fq(
      q,
      BigInt.parse(
          '0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE'),
    ),
    Fq(q, BigInt.zero)
  ]),
  "651": Fq2(q, [
    Fq(q, BigInt.zero),
    Fq(
      q,
      BigInt.parse(
          '0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE'),
    )
  ]),
  "652": Fq2(q, [
    Fq(
      q,
      BigInt.parse(
          '0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF'),
    ),
    Fq(q, BigInt.zero),
  ]),
  "1211": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8'),
      ),
      Fq(
        q,
        BigInt.parse(
            '0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3'),
      )
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1221": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFF'),
      ),
      Fq(q, BigInt.zero),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1231": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2'),
      ),
      Fq(
        q,
        BigInt.parse(
            '0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09'),
      ),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1241": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x5F19672FDF76CE51BA69C6076A0F77EADDB3A93BE6F89688DE17D813620A00022E01FFFFFFFEFFFE'),
      ),
      Fq(q, BigInt.zero),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1251": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995'),
      ),
      Fq(
        q,
        BigInt.parse(
            '0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116'),
      ),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1261": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAA'),
      ),
      Fq(q, BigInt.zero),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1271": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0xFC3E2B36C4E03288E9E902231F9FB854A14787B6C7B36FEC0C8EC971F63C5F282D5AC14D6C7EC22CF78A126DDC4AF3'),
      ),
      Fq(
        q,
        BigInt.parse(
            '0x1904D3BF02BB0667C231BEB4202C0D1F0FD603FD3CBD5F4F7B2443D784BAB9C4F67EA53D63E7813D8D0775ED92235FB8'),
      ),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1281": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAC'),
      ),
      Fq(q, BigInt.zero),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "1291": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x6AF0E0437FF400B6831E36D6BD17FFE48395DABC2D3435E77F76E17009241C5EE67992F72EC05F4C81084FBEDE3CC09'),
      ),
      Fq(
        q,
        BigInt.parse(
            '0x135203E60180A68EE2E9C448D77A2CD91C3DEDD930B1CF60EF396489F61EB45E304466CF3E67FA0AF1EE7B04121BDEA2'),
      ),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "12101": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x1A0111EA397FE699EC02408663D4DE85AA0D857D89759AD4897D29650FB85F9B409427EB4F49FFFD8BFD00000000AAAD'),
      ),
      Fq(q, BigInt.zero),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
  "12111": Fq6(q, [
    Fq2(q, [
      Fq(
        q,
        BigInt.parse(
            '0x5B2CFD9013A5FD8DF47FA6B48B1E045F39816240C0B8FEE8BEADF4D8E9C0566C63A3E6E257F87329B18FAE980078116'),
      ),
      Fq(
        q,
        BigInt.parse(
            '0x144E4211384586C16BD3AD4AFA99CC9170DF3560E77982D0DB45F3536814F0BD5871C1908BD478CD1EE605167FF82995'),
      ),
    ]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
    Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.zero)]),
  ]),
};
