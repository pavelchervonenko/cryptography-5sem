package com.pavel.crypto.math;

import java.math.BigInteger;

public class DefaultNumberTheoryService implements NumberTheoryService {

    @Override
    public int legendreSymbol(BigInteger a, BigInteger p) {
        if (p == null || a == null) {
            throw new IllegalArgumentException("Arguments must not be null");
        }

        if (!p.testBit(0)) {
            throw new IllegalArgumentException("p must be odd");
        }

        BigInteger aMod = a.mod(p);

        if (aMod.signum() == 0) {
            return 0;
        }

        BigInteger exponent = p.subtract(BigInteger.ONE).shiftRight(1);
        BigInteger result = modPow(aMod, exponent, p);

        if (result.equals(BigInteger.ONE)) {
            return 1;
        }

        BigInteger minusOne = p.subtract(BigInteger.ONE);

        if (result.equals(minusOne)) {
            return -1;
        }

        throw new IllegalStateException("Legendre symbol: unexpected result " + result);
    }

    @Override
    public int jacobiSymbol(BigInteger a, BigInteger n) {
        if (a == null || n == null) {
            throw new IllegalArgumentException("Arguments must not be null");
        }

        if (n.signum() <= 0) {
            throw new IllegalArgumentException("n must be positive");
        }

        if (!n.testBit(0)) {
            throw new IllegalArgumentException("n must be odd");
        }

        BigInteger aMod = a.mod(n);
        int result = 1;

        BigInteger zero = BigInteger.ZERO;
        BigInteger one = BigInteger.ONE;
        BigInteger two = BigInteger.TWO;
        BigInteger four = BigInteger.valueOf(4);
        BigInteger eight = BigInteger.valueOf(8);
        BigInteger three = BigInteger.valueOf(3);

        BigInteger currentA = aMod;
        BigInteger currentN = n;

        while (currentA.signum() != 0) {
            // Выносим степенную двойку: A = 2^s * A'
            while (!currentA.testBit(0)) {
                currentA = currentA.shiftRight(1);

                // Закон для (2|n): (2|n) = -1, если n ≡ 3 или 5 (mod 8)
                BigInteger nMod8 = currentN.mod(eight);

                if (nMod8.equals(BigInteger.valueOf(3))
                        || nMod8.equals(BigInteger.valueOf(5))) {
                    result = -result;
                }
            }

            // Перестановка (A, N) с учётом квадратичной взаимности
            BigInteger temp = currentA;
            currentA = currentN;
            currentN = temp;

            // Закон квадратичной взаимности:
            // (a|n) меняет знак, если a ≡ 3 (mod 4) и n ≡ 3 (mod 4)
            BigInteger aMod4 = currentA.mod(four);
            BigInteger nMod4 = currentN.mod(four);

            if (aMod4.equals(three) && nMod4.equals(three)) {
                result = -result;
            }

            currentA = currentA.mod(currentN);
        }

        if (currentN.equals(one)) {
            return result;
        }

        return 0;
    }


    @Override
    public BigInteger gcd(BigInteger a, BigInteger b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Arguments must not be null");
        }

        BigInteger x = a.abs();
        BigInteger y = b.abs();

        while (y.signum() != 0) {
            BigInteger r = x.mod(y);
            x = y;
            y = r;
        }

        return x;
    }

    @Override
    public ExtendedGcdResult extendedGcd(BigInteger a, BigInteger b) {
        if (a == null || b == null) {
            throw new IllegalArgumentException("Arguments must not be null");
        }

        BigInteger oldR = a;
        BigInteger r = b;

        BigInteger oldS = BigInteger.ONE;
        BigInteger s = BigInteger.ZERO;

        BigInteger oldT = BigInteger.ZERO;
        BigInteger t = BigInteger.ONE;

        while (r.signum() != 0) {
            BigInteger[] div = oldR.divideAndRemainder(r);
            BigInteger q = div[0];

            BigInteger tempR = r;
            r = div[1];
            oldR = tempR;

            BigInteger tempS = s;
            s = oldS.subtract(q.multiply(s));
            oldS = tempS;

            BigInteger tempT = t;
            t = oldT.subtract(q.multiply(t));
            oldT = tempT;
        }

        return new ExtendedGcdResult(oldR, oldS, oldT);
    }

    @Override
    public BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
        if (base == null || exponent == null || modulus == null) {
            throw new IllegalArgumentException("Arguments must not be null");
        }

        if (modulus.signum() <= 0) {
            throw new IllegalArgumentException("Modulus must be positive");
        }

        if (exponent.signum() < 0) {
            throw new IllegalArgumentException("Exponent must be non-negative");
        }

        BigInteger result = BigInteger.ONE;
        BigInteger b = base.mod(modulus);
        BigInteger e = exponent;

        while (e.signum() > 0) {
            if (e.testBit(0)) {
                result = result.multiply(b).mod(modulus);
            }

            b = b.multiply(b).mod(modulus);
            e = e.shiftRight(1);
        }

        return result;
    }
}
