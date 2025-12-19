package com.pavel.crypto.primality;

import com.pavel.crypto.math.NumberTheoryService;

import java.math.BigInteger;

public class FermatPrimalityTest extends AbstractProbabilisticPrimalityTest {

    public FermatPrimalityTest(NumberTheoryService numberTheory) {
        super(numberTheory);
    }

    @Override
    protected boolean runSingleIteration(BigInteger n, BigInteger a) {
        BigInteger g = numberTheory.gcd(a, n);

        if (!g.equals(BigInteger.ONE)) {
            return false;
        }

        BigInteger exponent = n.subtract(BigInteger.ONE);
        BigInteger value = numberTheory.modPow(a, exponent, n);

        if (!value.equals(BigInteger.ONE)) {
            return false;
        }

        return true;
    }
}
