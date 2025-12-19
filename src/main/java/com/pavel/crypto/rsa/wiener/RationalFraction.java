package com.pavel.crypto.rsa.wiener;

import java.math.BigInteger;

public class RationalFraction {

    private final BigInteger numerator;
    private final BigInteger denominator;

    public RationalFraction(BigInteger numerator, BigInteger denominator) {
        if (denominator.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Denominator must not be zero");
        }

        this.numerator = numerator;
        this.denominator = denominator;
    }

    public BigInteger getNumerator() {
        return numerator;
    }

    public BigInteger getDenominator() {
        return denominator;
    }
}
