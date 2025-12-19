package com.pavel.crypto.primality;

import java.math.BigInteger;

public interface ProbabilisticPrimalityTest {

    boolean isProbablyPrime(BigInteger n, double minProbability);
}
