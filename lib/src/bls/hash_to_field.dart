import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:quiver/iterables.dart';

import 'bls12381.dart';

const _byteMask = 0xFF;

/// Encode a BigInt into bytes using big-endian encoding.
Uint8List i2osp(BigInt val, int length) {
  if (val < BigInt.zero || val >= (BigInt.one >> (8 * length))) {
    throw AssertionError("bad I2OSP call: val=$val length=$length");
  }

  int size = (val.bitLength + 7) >> 3;
  var ret = Uint8List(size);
  for (int i = 0; i < size; i++) {
    ret[size - i - 1] = (val & BigInt.from(_byteMask)).toInt();
    val = val >> 8;
  }
  return ret;
}

//  defined in RFC 3447, section 4.2
BigInt os2ip(List<int> octects) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < octects.length; i++) {
    result += BigInt.from(octects[octects.length - i - 1]) << (8 * i);
  }
  return result;
}

//  expand_message_xmd from draft-irtf-cfrg-hash-to-curve-06
Uint8List _strxor(List<int> str1, List<int> str2) {
  return Uint8List.fromList(zip([str1, str2]).map((e) => e[0] ^ e[1]).toList());
}

Uint8List expandMessageXmd(
    List<int> msg, List<int> DST, int lenInBytes, Hash hashFn) {
  // input and output lengths for hash_fn
  var bInBytes = hashFn.convert([]).bytes.length;
  var rInBytes = hashFn.blockSize;

  // ell, DST_prime, etc
  var ell = (lenInBytes + bInBytes - 1) ~/ bInBytes;
  if (ell > 255) {
    throw AssertionError("expand_message_xmd: ell=$ell out of range");
  }
  var DSTPrime = DST + i2osp(BigInt.from(DST.length), 1);
  var ZPad = i2osp(BigInt.zero, rInBytes);
  var lIBStr = i2osp(BigInt.from(lenInBytes), 2);

  var b0 = hashFn
      .convert(ZPad + msg + lIBStr + i2osp(BigInt.zero, 1) + DSTPrime)
      .bytes;
  List<List<int>> bVals = List.filled(ell, [0]);
  bVals[0] = hashFn.convert(b0 + i2osp(BigInt.one, 1) + DSTPrime).bytes;
  for (int i = 1; i < ell; i++) {
    bVals[i] = hashFn
        .convert(
            _strxor(b0, bVals[i - 1]) + i2osp(BigInt.from(i + 1), 1) + DSTPrime)
        .bytes;
  }

  List<int> pseudoRandomBytes = [];
  for (var val in bVals) {
    pseudoRandomBytes.addAll(val);
  }

  return Uint8List.fromList(pseudoRandomBytes.sublist(0, lenInBytes));
}

// hash_to_field from draft-irtf-cfrg-hash-to-curve-06
List<List<BigInt>> hashToField(
    List<int> msg,
    int count,
    List<int> DST,
    BigInt modulus,
    int degree,
    int blen,
    Uint8List Function(List<int>, List<int>, int, Hash) expandFn,
    Hash hashFn) {
  // get pseudorandom bytes
  var lenInBytes = count * degree * blen;
  var pseudoRandomBytes = expandFn(msg, DST, lenInBytes, hashFn);

  List<List<BigInt>> uVals = List.filled(count, [BigInt.zero]);
  for (int i = 0; i < count; i++) {
    List<BigInt> eVals = [];
    for (int j = 0; j < degree; j++) {
      var elmOffset = blen * (j + i * degree);
      var tv = pseudoRandomBytes.sublist(elmOffset, elmOffset + blen);
      eVals[j] = os2ip(tv) % modulus;
    }
    uVals[i] = eVals;
  }
  return uVals;
}

List<List<BigInt>> Hp(List<int> msg, int count, List<int> dst) {
  return hashToField(msg, count, dst, q, 1, 64, expandMessageXmd, sha256);
}

List<List<BigInt>> Hp2(List<int> msg, int count, List<int> dst) {
  return hashToField(msg, count, dst, q, 2, 64, expandMessageXmd, sha256);
}
