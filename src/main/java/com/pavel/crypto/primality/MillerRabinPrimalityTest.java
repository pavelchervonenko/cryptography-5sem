package com.pavel.crypto.primality;

import com.pavel.crypto.math.NumberTheoryService;

import java.math.BigInteger;

public class MillerRabinPrimalityTest extends AbstractProbabilisticPrimalityTest {

    public MillerRabinPrimalityTest(NumberTheoryService numberTheory) {
        super(numberTheory);
    }

    @Override
    protected boolean runSingleIteration(BigInteger n, BigInteger a) {
        BigInteger nMinusOne = n.subtract(BigInteger.ONE);

        int s = 0;
        BigInteger d = nMinusOne;

        while (!d.testBit(0)) {
            d = d.shiftRight(1);
            s = s + 1;
        }

        BigInteger x = numberTheory.modPow(a, d, n);

        if (x.equals(BigInteger.ONE) || x.equals(nMinusOne)) {
            return true;
        }

        int r = 1;

        while (r < s) {
            x = x.multiply(x).mod(n);

            if (x.equals(nMinusOne)) {
                return true;
            }

            if (x.equals(BigInteger.ONE)) {
                return false;
            }

            r = r + 1;
        }

        return false;
    }
}
