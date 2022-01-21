import 'dart:typed_data';
import 'package:quiver/collection.dart';
import 'package:quiver/core.dart';
import 'package:quiver/iterables.dart';

import 'extensions/uint8list_extension.dart';

/// Finite Field
abstract class Field implements FieldOperators {
  abstract BigInt Q;
  abstract int extension;

  Field _zero(BigInt Q);
  Field _one(BigInt Q);
  Field _from(Fq fq);

  Field pow(BigInt exp);
  Field qiPow(int i);
  Field modSqrt();
  bool toBool();

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

  FieldExtBase create(BigInt Q, List<Field> fields);

  FieldExtBase fromBytes(Uint8List buffer, BigInt Q) {
    assert(buffer.length == extension * 48);
    var embeddedSize = 48 * (extension ~/ embedding);
    List<List<int>> tup = [];
    for (int i = 0; i < embedding; i++) {
      tup.add(buffer.sublist(i * embeddedSize, (i + 1) * embeddedSize));
    }
    return create(
        Q,
        tup.reversed
            .map((buffer) => Fq.fromBytes(Uint8List.fromList(buffer), Q))
            .toList());
  }

  @override
  bool toBool() => fields.any((element) => false);

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
      otherNew = other;
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
      throw UnimplementedError();
    }

    var buf = fields.map((field) => baseField._zero(Q)).toList();

    if (other is FieldExtBase) {
      fields.asMap().forEach((i, x) {
        if (extension == other.extension) {
          other.fields.asMap().forEach((j, y) {
            if (x.toBool() && y.toBool()) {
              if (i + j >= embedding) {
                buf[(i + j) % embedding] += x * y * root;
              } else {
                buf[(i + j) % embedding] += x * y;
              }
            }
          });
        } else {
          if (x.toBool()) {
            buf[i] = x * other;
          }
        }
      });
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
      throw UnimplementedError();
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

  Fq _zero(BigInt Q) => Fq(Q, BigInt.zero);

  Fq _one(BigInt Q) => Fq(Q, BigInt.one);

  Fq _from(Fq fq) => fq._clone();

  static Fq fromBytes(Uint8List bytes, BigInt Q) {
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
    return value.compareTo(other.value) == 0 || Q.compareTo(other.Q) == 0;
  }

  @override
  int get hashCode => hash2(Q, value);
  @override
  String toString();

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

  Fq _clone() => Fq(Q, value);

  @override
  Fq pow(BigInt exp) {
    if (exp.compareTo(BigInt.zero) == 0) {
      return Fq(Q, BigInt.one);
    } else if (exp.compareTo(BigInt.one) == 0) {
      return _clone();
    }
    if ((exp % BigInt.two).compareTo(BigInt.zero) == 0) {
      return Fq(Q, value * value).pow(exp ~/ BigInt.two);
    } else {
      return Fq(Q, value * value).pow(exp ~/ BigInt.two) * this;
    }
  }

  @override
  Fq qiPow(int i) => this;

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
