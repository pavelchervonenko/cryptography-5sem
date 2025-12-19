package com.pavel.crypto.math;

import java.math.BigInteger;

public class ExtendedGcdResult {

    private final BigInteger gcd;
    private final BigInteger x;
    private final BigInteger y;

    public ExtendedGcdResult(BigInteger gcd, BigInteger x, BigInteger y) {
        this.gcd = gcd;
        this.x = x;
        this.y = y;
    }

    public BigInteger getGcd() {
        return gcd;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }
}
