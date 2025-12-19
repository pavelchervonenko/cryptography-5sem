package com.pavel.crypto.gf256;

import java.math.BigInteger;
import java.util.List;

public interface Gf256Service {

    // сложение в GF(2^8): просто XOR
    byte add(byte a, byte b);

    // умножение по модулю многочлена степени 8 (модуль передаётся как байт)
    // модуль интерпретируется как x^8 + (младшие 8 бит)
    byte multiply(byte a, byte b, byte modulus);

    // обратный элемент по модулю многочлена степени 8
    byte inverse(byte a, byte modulus);

    // проверка, что бинарный многочлен степени 8 (x^8 + модуль) неприводим
    boolean isIrreducible(byte modulus);

    // коллекция всех неприводимых многочленов степени 8 (должно быть 30 штук)
    List<Byte> listIrreducibleDegree8();

    // разложение бинарного многочлена произвольной степени на неприводимые множители
    // многочлен представлен BigInteger, бит i = коэффициент при x^i
    List<BigInteger> factorBinaryPolynomial(BigInteger poly);
}
