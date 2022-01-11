import 'dart:typed_data';

extension ByteConversion on Uint8List {
  BigInt toBigInt() {
    BigInt r = BigInt.zero;

    for (final byte in this) {
      r = (r << 8) | BigInt.from(byte);
    }

    return r;
  }
}
