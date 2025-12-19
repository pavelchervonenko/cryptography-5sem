package com.pavel.crypto.primality;

import com.pavel.crypto.math.NumberTheoryService;

import java.math.BigInteger;

public class SolovayStrassenPrimalityTest extends AbstractProbabilisticPrimalityTest {

    public SolovayStrassenPrimalityTest(NumberTheoryService numberTheory) {
        super(numberTheory);
    }

    @Override
    protected boolean runSingleIteration(BigInteger n, BigInteger a) {
        BigInteger g = numberTheory.gcd(a, n);

        if (!g.equals(BigInteger.ONE)) {
            return false;
        }

        int jacobi = numberTheory.jacobiSymbol(a, n);

        BigInteger exponent = n.subtract(BigInteger.ONE).shiftRight(1);
        BigInteger mod = numberTheory.modPow(a, exponent, n);

        BigInteger expected;

        if (jacobi == -1) {
            expected = n.subtract(BigInteger.ONE);
        } else if (jacobi == 1) {
            expected = BigInteger.ONE;
        } else {
            return false;
        }

        if (!mod.equals(expected)) {
            return false;
        }

        return true;
    }
}
