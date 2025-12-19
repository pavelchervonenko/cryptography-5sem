package com.pavel.crypto.gf256;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Stateless-сервис для операций в GF(2^8).
 *
 * Элемент и модуль передаются как byte.
 * Модуль интерпретируется как бинарный многочлен степени 8:
 *   M(x) = x^8 + m7 x^7 + ... + m1 x + m0,
 * где биты байта modulus задают m0..m7.
 */
public class DefaultGf256Service implements Gf256Service {

    @Override
    public byte add(byte a, byte b) {
        return (byte) (a ^ b);
    }

    @Override
    public byte multiply(byte a, byte b, byte modulus) {
        int m = modulus & 0xFF;

        if (!isIrreducible(modulus)) {
            throw new ReduciblePolynomialException(
                    "Modulus x^8 + " + toPolynomialString(m) + " is reducible"
            );
        }

        int x = a & 0xFF;
        int y = b & 0xFF;
        int res = 0;

        int i = 0;
        while (i < 8) {
            if ((y & 1) != 0) {
                res = res ^ x;
            }

            boolean hiBit = (x & 0x80) != 0;

            x = (x << 1) & 0xFF;

            if (hiBit) {
                x = x ^ m;   // редукция по модулю (без x^8, он всегда 1)
            }

            y = y >>> 1;
            i = i + 1;
        }

        return (byte) res;
    }

    @Override
    public byte inverse(byte a, byte modulus) {
        int value = a & 0xFF;

        if (value == 0) {
            throw new IllegalArgumentException("Zero has no multiplicative inverse in GF(2^8)");
        }

        if (!isIrreducible(modulus)) {
            throw new ReduciblePolynomialException(
                    "Modulus x^8 + " + toPolynomialString(modulus & 0xFF) + " is reducible"
            );
        }

        // a^(2^8 - 2) = a^254 в GF(2^8)
        int exponent = 0xFE;

        byte result = (byte) 1;
        byte base = (byte) value;

        int e = exponent;

        while (e > 0) {
            if ((e & 1) != 0) {
                result = multiply(result, base, modulus);
            }

            base = multiply(base, base, modulus);
            e = e >>> 1;
        }

        return result;
    }

    @Override
    public boolean isIrreducible(byte modulus) {
        int mLow = modulus & 0xFF;

        // Полный многочлен степени 8: x^8 + (низ 8 бит)
        int f = (1 << 8) | mLow;

        // Проверяем делимость на все многочлены степени 1..4 (моноические).
        // Если какой-то делит без остатка — модуль приводим.
        for (int deg = 1; deg <= 4; deg++) {
            int maxMask = 1 << deg; // 2^deg вариантов низших коэффициентов

            for (int mask = 0; mask < maxMask; mask++) {
                int g = (1 << deg) | mask; // g(x) = x^deg + низ

                // степень 0 не берём, x^0+... здесь не появляется
                if (deg == 0) {
                    continue;
                }

                if (polyMod(f, g) == 0) {
                    return false;
                }
            }
        }

        return true;
    }

    @Override
    public List<Byte> listIrreducibleDegree8() {
        List<Byte> result = new ArrayList<>();

        for (int m = 0; m < 256; m++) {
            byte mod = (byte) m;

            if (isIrreducible(mod)) {
                result.add(mod);
            }
        }

        return Collections.unmodifiableList(result);
    }

    @Override
    public List<BigInteger> factorBinaryPolynomial(BigInteger poly) {
        if (poly == null) {
            throw new IllegalArgumentException("poly must not be null");
        }

        if (poly.signum() < 0) {
            throw new IllegalArgumentException("poly must be non-negative");
        }

        if (poly.equals(BigInteger.ZERO)) {
            return Collections.singletonList(BigInteger.ZERO);
        }

        List<BigInteger> factors = new ArrayList<>();
        factorRecursive(poly, factors);
        return factors;
    }

    // ========================== Вспомогательные ==========================

    // деление f(x) на g(x) в GF(2)[x], возвращаем остаток
    // f и g представлены как int, бит i = коэффициент при x^i
    private int polyMod(int f, int g) {
        if (g == 0) {
            throw new IllegalArgumentException("Division by zero polynomial");
        }

        int rem = f;
        int degG = degreeInt(g);

        while (true) {
            int degR = degreeInt(rem);

            if (degR < degG) {
                break;
            }

            int shift = degR - degG;
            rem = rem ^ (g << shift);
        }

        return rem;
    }

    private int degreeInt(int poly) {
        if (poly == 0) {
            return -1;
        }

        int deg = 31;

        while (deg >= 0 && ((poly >>> deg) & 1) == 0) {
            deg = deg - 1;
        }

        return deg;
    }

    private String toPolynomialString(int lowBits) {
        // только для сообщений об ошибках, не критично
        StringBuilder sb = new StringBuilder();

        sb.append("x^8");

        for (int i = 7; i >= 0; i--) {
            if (((lowBits >>> i) & 1) != 0) {
                sb.append(" + x^").append(i);
            }
        }

        return sb.toString();
    }

    // ---------- Факторизация произвольного двоичного многочлена ----------

    private void factorRecursive(BigInteger f, List<BigInteger> out) {
        int deg = degreeBig(f);

        if (deg <= 1) {
            out.add(f);
            return;
        }

        // пробуем найти нетривиальный делитель, перебирая многочлены меньшей степени
        BigInteger divisor = findNonTrivialDivisor(f);

        if (divisor == null) {
            // ничего не нашли — считаем f неприводимым
            out.add(f);
            return;
        }

        BigInteger[] div = polyDiv(f, divisor);

        BigInteger q = div[0];
        BigInteger r = div[1];

        if (!r.equals(BigInteger.ZERO)) {
            // не должно так быть, но на всякий случай
            out.add(f);
            return;
        }

        factorRecursive(divisor, out);
        factorRecursive(q, out);
    }

    // грубый поиск нетривиального делителя (для учебных степеней подходит)
    private BigInteger findNonTrivialDivisor(BigInteger f) {
        int degF = degreeBig(f);

        for (int d = 1; d <= degF / 2; d++) {
            int variants = 1 << d; // количество вариантов низших коэффициентов

            for (int mask = 0; mask < variants; mask++) {
                BigInteger g = BigInteger.ONE.shiftLeft(d)
                        .or(BigInteger.valueOf(mask));

                if (g.equals(BigInteger.ONE) || g.equals(f)) {
                    continue;
                }

                BigInteger[] div = polyDiv(f, g);

                if (div[1].equals(BigInteger.ZERO)) {
                    return g;
                }
            }
        }

        return null;
    }

    // деление многочленов над GF(2), poly / divisor
    private BigInteger[] polyDiv(BigInteger poly, BigInteger divisor) {
        if (divisor.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Division by zero polynomial");
        }

        BigInteger quotient = BigInteger.ZERO;
        BigInteger remainder = poly;

        int degDiv = degreeBig(divisor);

        while (true) {
            int degRem = degreeBig(remainder);

            if (degRem < degDiv) {
                break;
            }

            int shift = degRem - degDiv;

            quotient = quotient.setBit(shift);
            remainder = remainder.xor(divisor.shiftLeft(shift));
        }

        return new BigInteger[]{quotient, remainder};
    }

    private int degreeBig(BigInteger poly) {
        if (poly.equals(BigInteger.ZERO)) {
            return -1;
        }

        return poly.bitLength() - 1;
    }
}
