import 'dart:convert';
import 'dart:typed_data';
import 'package:convert/convert.dart';

final _byteMask = BigInt.from(0xff);

extension Uint8ListByteConversion on Uint8List {
  BigInt toBigInt() {
    BigInt r = BigInt.zero;

    for (final byte in this) {
      r = (r << 8) | BigInt.from(byte);
    }

    return r;
  }

  toHexString() => hex.encode(this);
}

extension BigIntByteConversion on BigInt {
  Uint8List toBytes({Endian endian = Endian.big}) {
    if (this < BigInt.zero) {
      throw AssertionError("Cannot convert signed BigInt");
    }
    var length = (bitLength + 7) >> 3;
    var r = Uint8List(length);
    var t = this;

    for (int i = length - 1; i >= 0; i--) {
      r[i] = (t & _byteMask).toInt();
      t = t >> 8;
    }

    return endian == Endian.big ? r : Uint8List.fromList(r.reversed.toList());
  }
}

extension IntByteConversion on int {
  Uint8List asUint32Bytes() => Uint8List(4)..buffer.asUint32List()[0] = this;
}

extension StringByteConversion on String {
  Uint8List utf8ToBytes() {
    return const Utf8Encoder().convert(this);
  }

  Uint8List hexToBytes() {
    if (length % 2 != 0) {
      throw Exception('Invalid input string, length must be multiple of 2');
    }

    Uint8List ret;
    if (startsWith('0x', 0) || startsWith('0X', 0)) {
      ret = Uint8List.fromList(hex.decode(substring(2)));
    } else {
      ret = Uint8List.fromList(hex.decode(this));
    }

    return ret;
  }
}
