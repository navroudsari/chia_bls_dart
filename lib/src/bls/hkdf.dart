import 'dart:typed_data';

import 'package:crypto/crypto.dart';

class HKDF256 {
  static const hashLength = 32;

  static Uint8List extract(Uint8List salt, Uint8List ikm) {
    Uint8List _salt;
    if (salt.isEmpty) {
      _salt = Uint8List.fromList([0]);
    } else {
      _salt = salt;
    }

    var h2 = Hmac(sha256, _salt);
    var digest = h2.convert(ikm);

    return Uint8List.fromList(digest.bytes);
  }

// L is the integer given by ceil((3 * ceil(log2(r))) / 16)
  static Uint8List expand(int L, Uint8List prk, Uint8List info) {
    assert(L <= 255 * hashLength);
    int N = (L / hashLength).ceil();
    int bytesWritten = 0;

    List<int> okm = [];
    Uint8List t = Uint8List.fromList([]);

    var h = Hmac(sha256, prk);
    for (int i = 1; i < N + 1; i++) {
      if (i == 1) {
        t = Uint8List.fromList(h.convert(info + [1]).bytes);
      } else {
        t = Uint8List.fromList(h.convert(t + info + [i]).bytes);
      }
      var toWrite = L - bytesWritten;
      if (toWrite > hashLength) toWrite = hashLength;
      okm.addAll(t.sublist(0, toWrite));
      bytesWritten += toWrite;
    }
    assert(bytesWritten == L);
    return Uint8List.fromList(okm);
  }

  static Uint8List extractExpand(
      int L, Uint8List key, Uint8List salt, Uint8List info) {
    var prk = extract(salt, key);
    return expand(L, prk, info);
  }
}
