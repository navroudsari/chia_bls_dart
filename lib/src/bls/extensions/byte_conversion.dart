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

extension ListByteConversion on List<int> {
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

    // Calculate the length in bytes from bitlength
    var l = ((bitLength + 8) >> 3);
    var m = l % 8;
    var r = m == 0 ? false : true;
    var lengthInBytes = r ? l - m + 8 : l;

    var b = Uint8List(lengthInBytes);
    var t = this;

    for (int i = lengthInBytes - 1; i >= 0; i--) {
      b[i] = (t & _byteMask).toInt();
      t = t >> 8;
    }

    return endian == Endian.big ? b : Uint8List.fromList(b.reversed.toList());
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
