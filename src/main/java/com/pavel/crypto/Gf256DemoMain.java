package com.pavel.crypto;

import com.pavel.crypto.gf256.DefaultGf256Service;
import com.pavel.crypto.gf256.Gf256Service;

import java.math.BigInteger;
import java.util.List;

public class Gf256DemoMain {

    public static void main(String[] args) {
        Gf256Service gf = new DefaultGf256Service();

        // Стандартный AES-модуль: x^8 + x^4 + x^3 + x + 1
        // Обычно кодируется как 0x1B (низ 8 бит)
        byte aesMod = (byte) 0x1B;

        System.out.println("AES modulus irreducible? " +
                gf.isIrreducible(aesMod));

        byte a = (byte) 0x57;
        byte b = (byte) 0x83;

        byte mul = gf.multiply(a, b, aesMod);
        System.out.printf("0x%02X * 0x%02X = 0x%02X in GF(2^8)\n",
                a & 0xFF, b & 0xFF, mul & 0xFF);

        byte inv = gf.inverse(a, aesMod);
        byte check = gf.multiply(a, inv, aesMod);

        System.out.printf("inv(0x%02X) = 0x%02X, check = 0x%02X\n",
                a & 0xFF, inv & 0xFF, check & 0xFF);

        List<Byte> irreducibles = gf.listIrreducibleDegree8();
        System.out.println("Количество неприводимых многочленов степени 8: " +
                irreducibles.size());

        // пример факторизации: (x^2 + x + 1)^2 = x^4 + 2x^3 + 3x^2 + 2x + 1
        // над GF(2): (x^2 + x + 1)^2 = x^4 + x^2 + 1
        BigInteger poly = new BigInteger("10101", 2); // x^4 + x^2 + 1

        List<BigInteger> factors = gf.factorBinaryPolynomial(poly);

        System.out.println("Факторы x^4 + x^2 + 1:");
        for (BigInteger f : factors) {
            System.out.println("  " + f.toString(2));
        }
    }
}
