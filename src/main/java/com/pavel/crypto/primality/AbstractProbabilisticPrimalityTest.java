package com.pavel.crypto.primality;

import com.pavel.crypto.math.NumberTheoryService;

import java.math.BigInteger;
import java.security.SecureRandom;

public abstract class AbstractProbabilisticPrimalityTest implements ProbabilisticPrimalityTest {

    protected final NumberTheoryService numberTheory;
    protected final SecureRandom random;

    protected AbstractProbabilisticPrimalityTest(NumberTheoryService numberTheory) {
        if (numberTheory == null) {
            throw new IllegalArgumentException("NumberTheoryService must not be null");
        }

        this.numberTheory = numberTheory;
        this.random = new SecureRandom();
    }

    @Override
    public boolean isProbablyPrime(BigInteger n, double minProbability) {
        if (n == null) {
            throw new IllegalArgumentException("n must not be null");
        }

        if (minProbability < 0.5 || minProbability >= 1.0) {
            throw new IllegalArgumentException("minProbability must be in [0.5, 1)");
        }

        if (n.compareTo(BigInteger.TWO) < 0) {
            return false;
        }

        if (n.equals(BigInteger.TWO) || n.equals(BigInteger.valueOf(3))) {
            return true;
        }

        if (!n.testBit(0)) {
            return false;
        }

        int iterations = computeIterations(minProbability);

        int i = 0;
        while (i < iterations) {
            BigInteger a = randomBase(n);
            boolean ok = runSingleIteration(n, a);

            if (!ok) {
                return false;
            }

            i = i + 1;
        }

        return true;
    }

    protected int computeIterations(double minProbability) {
        double maxError = 1.0 - minProbability;
        double log2Value = Math.log(1.0 / maxError) / Math.log(2.0);
        int k = (int) Math.ceil(log2Value);

        if (k < 1) {
            k = 1;
        }

        return k;
    }

    protected BigInteger randomBase(BigInteger n) {
        BigInteger two = BigInteger.TWO;
        BigInteger max = n.subtract(two);

        int bitLength = max.bitLength();
        BigInteger a = null;

        boolean done = false;
        while (!done) {
            BigInteger candidate = new BigInteger(bitLength, random);

            if (candidate.compareTo(two) >= 0 && candidate.compareTo(max) <= 0) {
                a = candidate;
                done = true;
            }
        }

        return a;
    }

    protected abstract boolean runSingleIteration(BigInteger n, BigInteger a);
}
