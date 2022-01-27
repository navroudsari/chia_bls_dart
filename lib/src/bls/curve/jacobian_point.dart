import '../fields.dart';
import 'ec.dart';

class JacobianPoint {
  //  Elliptic curve point, can represent any curve, and use Fq or Fq2
  //   coordinates. Uses Jacobian coordinates so that point addition
  //   does not require slow inversion.

  final bool isExtension;
  final bool infinity;
  final Field x;
  final Field y;
  final Field z;
  final EC ec;

  JacobianPoint(this.x, this.y, this.z, this.infinity, this.isExtension, EC? ec)
      : ec = ec ?? defaultEc {
    if ((x is! Fq) && (x is! FieldExtBase) ||
        ((y is! Fq) && (y is! FieldExtBase)) ||
        ((z is! Fq) && (z is! FieldExtBase))) {
      throw ArgumentError("x,y should be field elements");
    }
  }
}
