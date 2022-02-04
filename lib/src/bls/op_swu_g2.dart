import 'package:chia_bls_dart/src/bls/curve/ec.dart';

import 'bls12381.dart';
import 'curve/jacobian_point.dart';
import 'fields.dart';
import 'hash_to_field.dart';

int sgn0(Fq2 x) {
  // https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-07#section-4.1

  bool sign0 = (x.fields[0] as Fq).value % BigInt.two == BigInt.one;
  bool zero0 = (x.fields[0] as Fq).value == BigInt.zero;
  bool sign1 = (x.fields[1] as Fq).value % BigInt.two == BigInt.one;
  return sign0 || (zero0 && sign1) == true ? 1 : 0;
}

// distinguished non-square in Fp2 for SWU map
var xi2 = Fq2(q, [Fq(q, -BigInt.two), Fq(q, -BigInt.one)]);

//  3-isogenous curve parameters
var Ell2pA = Fq2(q, [Fq(q, BigInt.zero), Fq(q, BigInt.from(240))]);
var Ell2pB = Fq2(q, [Fq(q, BigInt.from(1012)), Fq(q, BigInt.from(1012))]);

//  eta values, used for computing sqrt(g(X1(t)))
//  For details on how to compute, see ../sage-impl/opt_sswu_g2.sage
var ev1 = BigInt.parse(
    '0x699BE3B8C6870965E5BF892AD5D2CC7B0E85A117402DFD83B7F4A947E02D978498255A2AAEC0AC627B5AFBDF1BF1C90');
var ev2 = BigInt.parse(
    '0x8157CD83046453F5DD0972B6E3949E4288020B5B8A9CC99CA07E27089A2CE2436D965026ADAD3EF7BABA37F2183E9B5');
var ev3 = BigInt.parse(
    '0xAB1C2FFDD6C253CA155231EB3E71BA044FD562F6F72BC5BAD5EC46A0B7A3B0247CF08CE6C6317F40EDBC653A72DEE17');
var ev4 = BigInt.parse(
    '0xAA404866706722864480885D68AD0CCAC1967C7544B447873CC37E0181271E006DF72162A3D3E0287BF597FBF7F8FC1');
var etas = [
  Fq2(q, [Fq(q, ev1), Fq(q, ev2)]),
  Fq2(q, [Fq(q, q - ev2), Fq(q, ev1)]),
  Fq2(q, [Fq(q, ev3), Fq(q, ev4)]),
  Fq2(q, [Fq(q, q - ev4), Fq(q, ev3)])
];

//  Simplified SWU map, optimized and adapted to Ell2'

//  This function maps an element of Fp^2 to the curve Ell2', 3-isogenous to Ell2.
JacobianPoint osswu2Help(Fq2 t) {
  //  first, compute X0(t), detecting and handling exceptional case
  var numDenCommon =
      xi2.pow(BigInt.two) * t.pow(BigInt.from(4)) + xi2 * t.pow(BigInt.two);
  var x0Num = Ell2pB * (numDenCommon + Fq(q, BigInt.one));
  var x0Den = -Ell2pA * numDenCommon;
  x0Den = x0Den == BigInt.zero ? Ell2pA * xi2 : x0Den;

  //  compute num and den of g(X0(t))
  var gx0Den = x0Den.pow(BigInt.from(3));
  var gx0Num = Ell2pB * gx0Den;
  gx0Num += Ell2pA * x0Num * x0Den.pow(BigInt.two);
  gx0Num += x0Num.pow(BigInt.from(3));

  //  try taking sqrt of g(X0(t))
  //  this uses the trick for combining division and sqrt from Section 5 of
  //  Bernstein, Duif, Lange, Schwabe, and Yang, "High-speed high-security signatures."
  //  J Crypt Eng 2(2):77--89, Sept. 2012. http://ed25519.cr.yp.to/ed25519-20110926.pdf
  var tmp1 = gx0Den.pow(BigInt.from(7)); // v^7;
  var tmp2 = gx0Num * tmp1; // u v^7;
  tmp1 = tmp1 * tmp2 * gx0Den; // u v^15;
  var sqrtCandidate =
      tmp2 * tmp1.pow((q.pow(2) - BigInt.from(9)) ~/ BigInt.from(16));

  //  check if g(X0(t)) is square and return the sqrt if so
  for (var root in rootsOfUnity) {
    var y0 = sqrtCandidate * root as Fq2;
    if (y0.pow(BigInt.two) * gx0Den == gx0Num) {
      //  found sqrt(g(X0(t))). force sign of y to equal sign of t
      if (sgn0(y0) != sgn0(t)) {
        y0 = -y0 as Fq2;
      }
      assert(sgn0(y0) == sgn0(t));
      return JacobianPoint(x0Num * x0Den, y0 * x0Den.pow(BigInt.from(3)), x0Den,
          false, defaultEcTwist);
    }
  }

  //  if we've gotten here, then g(X0(t)) is not square. convert srqt_candidate to sqrt(g(X1(t)))
  var x1Num = xi2 * t.pow(BigInt.two) * x0Num, x1Den = x0Den;
  var gx1Num = xi2.pow(BigInt.from(3)) * t.pow(BigInt.from(6)) * gx0Num,
      gx1Den = gx0Den;
  sqrtCandidate *= t.pow(BigInt.from(3));
  for (var eta in etas) {
    var y1 = eta * sqrtCandidate as Fq2;
    if (y1.pow(BigInt.two) * gx1Den == gx1Num) {
      //  found sqrt(g(X1(t))). force sign of y to equal sign of t
      if (sgn0(y1) != sgn0(t)) {
        y1 = -y1 as Fq2;
      }
      assert(sgn0(y1) == sgn0(t));
      return JacobianPoint(x1Num * x1Den, y1 * x1Den.pow(BigInt.from(3)), x1Den,
          false, defaultEcTwist);
    }
  }

  //  if we got here, something is wrong
  throw StateError("osswu2_help failed for unknown reasons");
}

// compute 3-isogeny map from Ell2' to Ell2
JacobianPoint iso3(P) {
  return evalIso(P, [xnum, xden, ynum, yden], defaultEcTwist);
}

//  map from Fq2 element(s) to point in G2 subgroup of Ell2
JacobianPoint optSwu2Map(Fq2 t, Fq2? t2) {
  var Pp = iso3(osswu2Help(t));
  if (t2 != null) {
    var Pp2 = iso3(osswu2Help(t2));
    Pp = Pp + Pp2;
  }
  return Pp * hEff;
}

//  map from bytes() to point in G2 subgroup of Ell2
JacobianPoint g2Map(List<int> alpha, List<int> dst) {
  var f = Hp2(alpha, 2, dst)
      .map((hh) => Fq2(q, hh.map((bn) => Fq(q, bn)).toList()))
      .toList();
  return optSwu2Map(f[0], f[1]);
}

//
//  3-Isogeny from Ell2' to Ell2
//
//  coefficients for the 3-isogeny map from Ell2' to Ell2
var xnum = [
      Fq2(q, [
        Fq(
            q,
            BigInt.parse(
                '0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97D6')),
        Fq(
            q,
            BigInt.parse(
                '0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97D6'))
      ]),
      Fq2(
        q,
        [
          Fq(q, BigInt.parse('0x0')),
          Fq(
              q,
              BigInt.parse(
                  '0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71A'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(
              q,
              BigInt.parse(
                  '0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71E')),
          Fq(
              q,
              BigInt.parse(
                  '0x8AB05F8BDD54CDE190937E76BC3E447CC27C3D6FBD7063FCD104635A790520C0A395554E5C6AAAA9354FFFFFFFFE38D'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(
              q,
              BigInt.parse(
                  '0x171D6541FA38CCFAED6DEA691F5FB614CB14B4E7F4E810AA22D6108F142B85757098E38D0F671C7188E2AAAAAAAA5ED1')),
          Fq(q, BigInt.parse('0x0'))
        ],
      ),
    ],
    xden = [
      Fq2(
        q,
        [
          Fq(q, BigInt.parse('0x0')),
          Fq(
              q,
              BigInt.parse(
                  '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA63'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(q, BigInt.parse('0xC')),
          Fq(
              q,
              BigInt.parse(
                  '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA9F'))
        ],
      ),
      Fq2(q, [Fq(q, BigInt.one), Fq(q, BigInt.zero)]),
    ],
    ynum = [
      Fq2(
        q,
        [
          Fq(
              q,
              BigInt.parse(
                  '0x1530477C7AB4113B59A4C18B076D11930F7DA5D4A07F649BF54439D87D27E500FC8C25EBF8C92F6812CFC71C71C6D706')),
          Fq(
              q,
              BigInt.parse(
                  '0x1530477C7AB4113B59A4C18B076D11930F7DA5D4A07F649BF54439D87D27E500FC8C25EBF8C92F6812CFC71C71C6D706'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(q, BigInt.zero),
          Fq(
              q,
              BigInt.parse(
                  '0x5C759507E8E333EBB5B7A9A47D7ED8532C52D39FD3A042A88B58423C50AE15D5C2638E343D9C71C6238AAAAAAAA97BE'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(
              q,
              BigInt.parse(
                  '0x11560BF17BAA99BC32126FCED787C88F984F87ADF7AE0C7F9A208C6B4F20A4181472AAA9CB8D555526A9FFFFFFFFC71C')),
          Fq(
              q,
              BigInt.parse(
                  '0x8AB05F8BDD54CDE190937E76BC3E447CC27C3D6FBD7063FCD104635A790520C0A395554E5C6AAAA9354FFFFFFFFE38F'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(
              q,
              BigInt.parse(
                  '0x124C9AD43B6CF79BFBF7043DE3811AD0761B0F37A1E26286B0E977C69AA274524E79097A56DC4BD9E1B371C71C718B10')),
          Fq(q, BigInt.zero)
        ],
      ),
    ],
    yden = [
      Fq2(
        q,
        [
          Fq(
              q,
              BigInt.parse(
                  '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA8FB')),
          Fq(
              q,
              BigInt.parse(
                  '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA8FB'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(q, BigInt.zero),
          Fq(
              q,
              BigInt.parse(
                  '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFA9D3'))
        ],
      ),
      Fq2(
        q,
        [
          Fq(q, BigInt.parse('0x12')),
          Fq(
              q,
              BigInt.parse(
                  '0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAA99'))
        ],
      ),
      Fq2(q, [Fq(q, BigInt.one), Fq(q, BigInt.zero)]),
    ];
