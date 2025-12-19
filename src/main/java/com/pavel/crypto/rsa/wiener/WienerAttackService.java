package com.pavel.crypto.rsa.wiener;

import com.pavel.crypto.rsa.RsaPublicKey;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class WienerAttackService {

    public WienerAttackResult attack(RsaPublicKey publicKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("publicKey must not be null");
        }

        BigInteger e = publicKey.getExponent();
        BigInteger n = publicKey.getModulus();

        List<BigInteger> cf = continuedFraction(e, n);

        List<RationalFraction> convergents = buildConvergents(cf);

        BigInteger foundD = null;
        BigInteger foundPhi = null;
        boolean success = false;

        for (RationalFraction frac : convergents) {
            BigInteger k = frac.getNumerator();
            BigInteger d = frac.getDenominator();

            if (k.equals(BigInteger.ZERO)) {
                continue;
            }

            BigInteger edMinus1 = e.multiply(d).subtract(BigInteger.ONE);

            if (!edMinus1.mod(k).equals(BigInteger.ZERO)) {
                continue;
            }

            BigInteger phiCandidate = edMinus1.divide(k);

            BigInteger s = n.subtract(phiCandidate).add(BigInteger.ONE);

            BigInteger discriminant = s.multiply(s).subtract(n.shiftLeft(2));

            if (discriminant.signum() < 0) {
                continue;
            }

            BigInteger sqrtDisc = integerSqrt(discriminant);

            if (!sqrtDisc.multiply(sqrtDisc).equals(discriminant)) {
                continue;
            }

            BigInteger p = s.add(sqrtDisc).shiftRight(1);
            BigInteger q = s.subtract(sqrtDisc).shiftRight(1);

            if (!p.multiply(q).equals(n)) {
                continue;
            }

            foundD = d;
            foundPhi = phiCandidate;
            success = true;
            break;
        }

        return new WienerAttackResult(success, foundD, foundPhi, convergents);
    }

    private List<BigInteger> continuedFraction(BigInteger numerator, BigInteger denominator) {
        List<BigInteger> coeffs = new ArrayList<>();

        BigInteger a = numerator;
        BigInteger b = denominator;

        while (!b.equals(BigInteger.ZERO)) {
            BigInteger[] div = a.divideAndRemainder(b);
            BigInteger q = div[0];
            BigInteger r = div[1];

            coeffs.add(q);

            a = b;
            b = r;
        }

        return coeffs;
    }

    private List<RationalFraction> buildConvergents(List<BigInteger> cf) {
        List<RationalFraction> result = new ArrayList<>();

        BigInteger hMinusTwo = BigInteger.ZERO;
        BigInteger hMinusOne = BigInteger.ONE;
        BigInteger kMinusTwo = BigInteger.ONE;
        BigInteger kMinusOne = BigInteger.ZERO;

        int i = 0;

        while (i < cf.size()) {
            BigInteger a = cf.get(i);

            BigInteger h = a.multiply(hMinusOne).add(hMinusTwo);
            BigInteger k = a.multiply(kMinusOne).add(kMinusTwo);

            result.add(new RationalFraction(h, k));

            hMinusTwo = hMinusOne;
            hMinusOne = h;
            kMinusTwo = kMinusOne;
            kMinusOne = k;

            i = i + 1;
        }

        return result;
    }

    private BigInteger integerSqrt(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("value must be non-negative");
        }

        if (value.compareTo(BigInteger.ONE) <= 0) {
            return value;
        }

        BigInteger two = BigInteger.TWO;
        BigInteger x = value.shiftRight(value.bitLength() / 2);
        BigInteger lastX = BigInteger.ZERO;

        boolean changed = true;

        while (changed) {
            BigInteger xNext = x.add(value.divide(x)).divide(two);

            if (xNext.equals(x) || xNext.equals(lastX)) {
                changed = false;
            }

            lastX = x;
            x = xNext;
        }

        while (x.multiply(x).compareTo(value) > 0) {
            x = x.subtract(BigInteger.ONE);
        }

        return x;
    }
}
