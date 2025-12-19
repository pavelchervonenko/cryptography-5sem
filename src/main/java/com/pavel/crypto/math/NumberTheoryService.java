package com.pavel.crypto.math;

import java.math.BigInteger;

public interface NumberTheoryService {

    int legendreSymbol(BigInteger a, BigInteger p);

    int jacobiSymbol(BigInteger a, BigInteger n);

    BigInteger gcd(BigInteger a, BigInteger b);

    ExtendedGcdResult extendedGcd(BigInteger a, BigInteger b);

    BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus);
}
