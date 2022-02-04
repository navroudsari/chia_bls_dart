import 'dart:convert';
import 'dart:typed_data';

final _byteMask = BigInt.from(0xff);

extension Uint8ListByteConversion on Uint8List {
  BigInt toBigInt() {
    BigInt r = BigInt.zero;

    for (final byte in this) {
      r = (r << 8) | BigInt.from(byte);
    }

    return r;
  }
}

extension BigIntByteConversion on BigInt {
  Uint8List toBytes({Endian endian = Endian.big}) {
    if (this < BigInt.zero) {
      throw AssertionError("Cannot convert signed BigInt");
    }
    var length = (bitLength + 7) >> 3;
    var r = Uint8List(length);
    var t = this;

    for (int i = length - 1; i == 0; i--) {
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
}
