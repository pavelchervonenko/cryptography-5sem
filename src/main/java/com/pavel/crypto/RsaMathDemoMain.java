package com.pavel.crypto;

import com.pavel.crypto.math.DefaultNumberTheoryService;
import com.pavel.crypto.math.ExtendedGcdResult;
import com.pavel.crypto.math.NumberTheoryService;
import com.pavel.crypto.primality.FermatPrimalityTest;
import com.pavel.crypto.primality.MillerRabinPrimalityTest;
import com.pavel.crypto.primality.ProbabilisticPrimalityTest;
import com.pavel.crypto.primality.SolovayStrassenPrimalityTest;
import com.pavel.crypto.rsa.RsaKeyPair;
import com.pavel.crypto.rsa.RsaPrivateKey;
import com.pavel.crypto.rsa.RsaPublicKey;
import com.pavel.crypto.rsa.RsaService;
import com.pavel.crypto.rsa.wiener.RationalFraction;
import com.pavel.crypto.rsa.wiener.WienerAttackResult;
import com.pavel.crypto.rsa.wiener.WienerAttackService;

import java.math.BigInteger;
import java.util.List;

public class RsaMathDemoMain {

    public static void main(String[] args) {
        NumberTheoryService nt = new DefaultNumberTheoryService();

        System.out.println("===== 1. NumberTheoryService demo =====");
        demoNumberTheory(nt);

        System.out.println();
        System.out.println("===== 2. Probabilistic primality tests demo =====");
        demoPrimalityTests(nt);

        System.out.println();
        System.out.println("===== 3. RSA keygen + encrypt/decrypt demo =====");
        demoRsa(nt);

        System.out.println();
        System.out.println("===== 4. Wiener attack demo =====");
        demoWienerAttack(nt);
    }

    // ----------------- 1. Number theory demo -----------------

    private static void demoNumberTheory(NumberTheoryService nt) {
        // gcd
        BigInteger a = BigInteger.valueOf(48);
        BigInteger b = BigInteger.valueOf(18);
        BigInteger g = nt.gcd(a, b);

        System.out.println("gcd(48, 18) = " + g + " (ожидаем 6)");

        // extended gcd
        BigInteger a2 = BigInteger.valueOf(240);
        BigInteger b2 = BigInteger.valueOf(46);

        ExtendedGcdResult eg = nt.extendedGcd(a2, b2);

        BigInteger checkBezout = a2.multiply(eg.getX()).add(b2.multiply(eg.getY()));

        System.out.println("extendedGcd(240, 46): gcd = " + eg.getGcd());
        System.out.println("x = " + eg.getX() + ", y = " + eg.getY());
        System.out.println("Проверка Bezout: 240*x + 46*y = " + checkBezout);

        // modPow
        BigInteger base = BigInteger.valueOf(2);
        BigInteger exp = BigInteger.valueOf(20);
        BigInteger mod = BigInteger.valueOf(1009);

        BigInteger mp = nt.modPow(base, exp, mod);

        System.out.println("2^20 mod 1009 = " + mp + " (ожидаем 225)");

        // Legendre symbol (a|p), p = 11
        BigInteger p = BigInteger.valueOf(11);
        BigInteger aLeg1 = BigInteger.valueOf(5);
        BigInteger aLeg2 = BigInteger.valueOf(2);

        int leg1 = nt.legendreSymbol(aLeg1, p);
        int leg2 = nt.legendreSymbol(aLeg2, p);

        System.out.println("Legendre(5 | 11) = " + leg1 + " (ожидаем 1)");
        System.out.println("Legendre(2 | 11) = " + leg2 + " (ожидаем -1)");

        // Jacobi symbol (5 | 21) = (5|3)*(5|7) = (-1)*(-1) = 1
        BigInteger nJac = BigInteger.valueOf(21);
        BigInteger aJac = BigInteger.valueOf(5);
        int jac = nt.jacobiSymbol(aJac, nJac);

        System.out.println("Jacobi(5 | 21) = " + jac + " (ожидаем 1)");
    }

    // ------------- 2. Probabilistic primality tests demo --------------

    private static void demoPrimalityTests(NumberTheoryService nt) {
        BigInteger prime = BigInteger.valueOf(101);
        BigInteger composite = BigInteger.valueOf(221); // 13 * 17

        double minProbability = 0.99;

        ProbabilisticPrimalityTest fermat =
                new FermatPrimalityTest(nt);
        ProbabilisticPrimalityTest solovay =
                new SolovayStrassenPrimalityTest(nt);
        ProbabilisticPrimalityTest millerRabin =
                new MillerRabinPrimalityTest(nt);

        System.out.println("Число 101 (простое):");
        System.out.println("  Ферма:           " +
                fermat.isProbablyPrime(prime, minProbability));
        System.out.println("  Соловей-Штрассен: " +
                solovay.isProbablyPrime(prime, minProbability));
        System.out.println("  Миллер-Рабин:    " +
                millerRabin.isProbablyPrime(prime, minProbability));

        System.out.println("Число 221 (составное):");
        System.out.println("  Ферма:           " +
                fermat.isProbablyPrime(composite, minProbability));
        System.out.println("  Соловей-Штрассен: " +
                solovay.isProbablyPrime(composite, minProbability));
        System.out.println("  Миллер-Рабин:    " +
                millerRabin.isProbablyPrime(composite, minProbability));
    }

    // ------------- 3. RSA demo (генерация, шифр, расшифр) --------------

    private static void demoRsa(NumberTheoryService nt) {
        // маленькая битовая длина для быстрого демо; для реальной крипты надо >= 2048
        int bitLength = 64;
        double minProb = 0.99;

        RsaService rsaService = new RsaService(
                RsaService.PrimalityTestType.MILLER_RABIN,
                minProb,
                bitLength,
                nt
        );

        System.out.println("Генерация ключевой пары RSA...");
        RsaKeyPair keyPair = rsaService.generateNewKeyPair();
        RsaPublicKey pub = keyPair.getPublicKey();
        RsaPrivateKey priv = keyPair.getPrivateKey();

        System.out.println("n (modulus) bitLength = " +
                pub.getModulus().bitLength());
        System.out.println("e = " + pub.getExponent());
        System.out.println("d bitLength = " +
                priv.getExponent().bitLength());

        BigInteger message = BigInteger.valueOf(12345);

        System.out.println("Сообщение m = " + message);

        BigInteger ciphertext = rsaService.encrypt(message, pub);
        BigInteger decrypted = rsaService.decrypt(ciphertext, priv);

        System.out.println("Ciphertext c = " + ciphertext);
        System.out.println("Decrypted m' = " + decrypted);
        System.out.println("Успех (m == m')? " +
                message.equals(decrypted));
    }

    // ------------- 4. Wiener attack demo -------------------

    private static void demoWienerAttack(NumberTheoryService nt) {
        WienerAttackService wiener = new WienerAttackService();

        // 4.1 Попытка атаки на безопасный ключ (сгенерированный выше стилем нашего генератора)
        System.out.println("4.1 Атака Винера на безопасный ключ (ожидаем провал):");

        int bitLength = 64;
        double minProb = 0.99;

        RsaService safeRsaService = new RsaService(
                RsaService.PrimalityTestType.MILLER_RABIN,
                minProb,
                bitLength,
                nt
        );

        RsaKeyPair safePair = safeRsaService.generateNewKeyPair();
        RsaPublicKey safePub = safePair.getPublicKey();

        WienerAttackResult safeResult = wiener.attack(safePub);

        System.out.println("Успех атаки? " + safeResult.isSuccess());

        // 4.2 Атака Винера на действительно слабый ключ (ожидаем успех):

        System.out.println();
        System.out.println("4.2 Атака Винера на слабый ключ (ожидаем успех):");

        // Игрушечный слабый ключ:
        BigInteger p = BigInteger.valueOf(41);
        BigInteger q = BigInteger.valueOf(167);
        BigInteger n = p.multiply(q);             // 6847
        BigInteger phi = p.subtract(BigInteger.ONE)
                .multiply(q.subtract(BigInteger.ONE)); // 6640
        BigInteger d = BigInteger.valueOf(3);

        // e — обратный к d по модулю phi
        ExtendedGcdResult egForE = nt.extendedGcd(d, phi);
        BigInteger e = egForE.getX().mod(phi);

        System.out.println("n = " + n + ", phi(n) = " + phi);
        System.out.println("Выбранный маленький d = " + d);
        System.out.println("Соответствующий e    = " + e);

        RsaPublicKey weakPub = new RsaPublicKey(n, e);

        WienerAttackResult weakResult = wiener.attack(weakPub);

        System.out.println("Успех атаки? " + weakResult.isSuccess());

        if (weakResult.isSuccess()) {
            System.out.println("Найденное d      = " + weakResult.getD() +
                    " (ожидаем 3)");
            System.out.println("Найденное φ(n)   = " + weakResult.getPhi() +
                    " (ожидаем 6640)");

            List<RationalFraction> convergents = weakResult.getConvergents();

            System.out.println("Первые несколько подходящих дробей (k/d):");
            int limit = convergents.size();

            if (limit > 8) {
                limit = 8;
            }

            for (int i = 0; i < limit; i++) {
                RationalFraction frac = convergents.get(i);
                System.out.println("  " + (i + 1) + ": " +
                        frac.getNumerator() + " / " +
                        frac.getDenominator());
            }
        } else {
            System.out.println("Атака не сработала на слабом ключе — нужно проверить реализацию.");
        }
    }
}
