package com.pavel.crypto.rsa.wiener;

import java.math.BigInteger;
import java.util.List;

public class WienerAttackResult {

    private final boolean success;
    private final BigInteger d;
    private final BigInteger phi;
    private final List<RationalFraction> convergents;

    public WienerAttackResult(boolean success,
                              BigInteger d,
                              BigInteger phi,
                              List<RationalFraction> convergents) {
        this.success = success;
        this.d = d;
        this.phi = phi;
        this.convergents = convergents;
    }

    public boolean isSuccess() {
        return success;
    }

    public BigInteger getD() {
        return d;
    }

    public BigInteger getPhi() {
        return phi;
    }

    public List<RationalFraction> getConvergents() {
        return convergents;
    }
}
