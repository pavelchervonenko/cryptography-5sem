package com.pavel.crypto.rsa;

import com.pavel.crypto.math.ExtendedGcdResult;
import com.pavel.crypto.math.NumberTheoryService;
import com.pavel.crypto.primality.FermatPrimalityTest;
import com.pavel.crypto.primality.MillerRabinPrimalityTest;
import com.pavel.crypto.primality.ProbabilisticPrimalityTest;
import com.pavel.crypto.primality.SolovayStrassenPrimalityTest;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RsaService {

    public enum PrimalityTestType {
        FERMAT,
        SOLOVAY_STRASSEN,
        MILLER_RABIN
    }

    public static class KeyGenerator {

        private final ProbabilisticPrimalityTest primalityTest;
        private final double minProbability;
        private final int bitLength;
        private final NumberTheoryService numberTheory;
        private final SecureRandom random;

        public KeyGenerator(PrimalityTestType testType,
                            double minProbability,
                            int bitLength,
                            NumberTheoryService numberTheory) {

            if (minProbability < 0.5 || minProbability >= 1.0) {
                throw new IllegalArgumentException("minProbability must be in [0.5, 1)");
            }

            if (bitLength < 16) {
                throw new IllegalArgumentException("bitLength is too small");
            }

            if (numberTheory == null) {
                throw new IllegalArgumentException("NumberTheoryService must not be null");
            }

            this.minProbability = minProbability;
            this.bitLength = bitLength;
            this.numberTheory = numberTheory;
            this.random = new SecureRandom();
            this.primalityTest = createTest(testType, numberTheory);
        }

        private ProbabilisticPrimalityTest createTest(PrimalityTestType type,
                                                      NumberTheoryService numberTheory) {
            if (type == PrimalityTestType.FERMAT) {
                return new FermatPrimalityTest(numberTheory);
            }

            if (type == PrimalityTestType.SOLOVAY_STRASSEN) {
                return new SolovayStrassenPrimalityTest(numberTheory);
            }

            if (type == PrimalityTestType.MILLER_RABIN) {
                return new MillerRabinPrimalityTest(numberTheory);
            }

            throw new IllegalArgumentException("Unsupported primality test type: " + type);
        }

        public RsaKeyPair generateKeyPair() {
            boolean generated = false;

            RsaKeyPair pair = null;

            while (!generated) {
                BigInteger p = generatePrime();
                BigInteger q = generatePrimeDifferentFrom(p);

                BigInteger n = p.multiply(q);
                BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

                BigInteger e = BigInteger.valueOf(65537L);

                if (!numberTheory.gcd(e, phi).equals(BigInteger.ONE)) {
                    continue;
                }

                ExtendedGcdResult egcd = numberTheory.extendedGcd(e, phi);

                if (!egcd.getGcd().equals(BigInteger.ONE)) {
                    continue;
                }

                BigInteger d = egcd.getX().mod(phi);

                if (d.signum() <= 0) {
                    d = d.add(phi);
                }

                if (!isFermatSafe(p, q)) {
                    continue;
                }

                if (!isWienerSafe(n, d)) {
                    continue;
                }

                RsaPublicKey publicKey = new RsaPublicKey(n, e);
                RsaPrivateKey privateKey = new RsaPrivateKey(n, d);

                pair = new RsaKeyPair(publicKey, privateKey);
                generated = true;
            }

            return pair;
        }

        private BigInteger generatePrime() {
            BigInteger candidate = randomOddWithBitLength(bitLength);

            boolean prime = false;

            while (!prime) {
                if (primalityTest.isProbablyPrime(candidate, minProbability)) {
                    prime = true;
                } else {
                    candidate = candidate.add(BigInteger.TWO);
                }
            }

            return candidate;
        }

        private BigInteger randomOddWithBitLength(int bits) {
            BigInteger value = null;
            boolean ok = false;

            while (!ok) {
                BigInteger candidate = new BigInteger(bits, random);
                candidate = candidate.setBit(bits - 1);

                if (!candidate.testBit(0)) {
                    candidate = candidate.add(BigInteger.ONE);
                }

                value = candidate;
                ok = true;
            }

            return value;
        }

        private BigInteger generatePrimeDifferentFrom(BigInteger p) {
            BigInteger q = generatePrime();

            boolean equal = q.equals(p);

            while (equal) {
                q = generatePrime();
                equal = q.equals(p);
            }

            return q;
        }

        private boolean isFermatSafe(BigInteger p, BigInteger q) {
            BigInteger diff = p.subtract(q).abs();
            int diffBits = diff.bitLength();
            int target = bitLength / 2;

            if (diffBits <= target) {
                return false;
            }

            return true;
        }

        private boolean isWienerSafe(BigInteger n, BigInteger d) {
            int nBits = n.bitLength();
            int minDBits = nBits / 4 + 1;

            if (d.bitLength() < minDBits) {
                return false;
            }

            return true;
        }
    }

    private final NumberTheoryService numberTheory;
    private final KeyGenerator keyGenerator;

    public RsaService(PrimalityTestType testType,
                      double minPrimeProbability,
                      int bitLength,
                      NumberTheoryService numberTheory) {
        if (numberTheory == null) {
            throw new IllegalArgumentException("NumberTheoryService must not be null");
        }

        this.numberTheory = numberTheory;
        this.keyGenerator = new KeyGenerator(testType, minPrimeProbability, bitLength, numberTheory);
    }

    public RsaKeyPair generateNewKeyPair() {
        return keyGenerator.generateKeyPair();
    }

    public BigInteger encrypt(BigInteger message, RsaPublicKey key) {
        if (message == null || key == null) {
            throw new IllegalArgumentException("Arguments must not be null");
        }

        BigInteger n = key.getModulus();
        BigInteger e = key.getExponent();

        if (message.signum() < 0 || message.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Message must be in [0, n)");
        }

        return numberTheory.modPow(message, e, n);
    }

    public BigInteger decrypt(BigInteger ciphertext, RsaPrivateKey key) {
        if (ciphertext == null || key == null) {
            throw new IllegalArgumentException("Arguments must not be null");
        }

        BigInteger n = key.getModulus();
        BigInteger d = key.getExponent();

        if (ciphertext.signum() < 0 || ciphertext.compareTo(n) >= 0) {
            throw new IllegalArgumentException("Ciphertext must be in [0, n)");
        }

        return numberTheory.modPow(ciphertext, d, n);
    }
}
