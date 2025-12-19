package com.pavel.crypto;

import com.pavel.crypto.rsa.RsaFileCryptoService;
import com.pavel.crypto.rsa.RsaService;
import com.pavel.crypto.rsa.RsaKeyPair;
import com.pavel.crypto.rsa.RsaPublicKey;
import com.pavel.crypto.rsa.RsaPrivateKey;
import com.pavel.crypto.math.DefaultNumberTheoryService;
import com.pavel.crypto.math.NumberTheoryService;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.Future;

public class RsaFileDemoMain {

    public static void main(String[] args) throws Exception {
        // 1. Файлы (подправь пути под себя)
        Path inputFile = Paths.get("src/main/testdata/monkey.jpg");
        Path encryptedFile = Paths.get("src/main/testdata/input_rsa.enc");
        Path decryptedFile = Paths.get("src/main/testdata/input_rsa.dec.jpg");


        if (!Files.exists(inputFile)) {
            System.out.println("Файл " + inputFile + " не найден. Положи туда какой-нибудь файл.");
            return;
        }

        /// 2. Числовой сервис и RSA-сервис (пакеты/конструктор подстрой под свой код)
        NumberTheoryService nts = new DefaultNumberTheoryService();

        // Например, используем Миллера–Рабина с вероятностью >= 0.999
        // и 512-битными кандидатами (это именно тот int, который требует твой конструктор).
        RsaService rsaService = new RsaService(
                RsaService.PrimalityTestType.MILLER_RABIN,
                0.999,
                512,
                nts
        );

        // Например, 1024-битный модуль
        int modulusBits = 1024;

        System.out.println("Генерация RSA-ключевой пары (" + modulusBits + " бит)...");
        RsaKeyPair keyPair = rsaService.generateNewKeyPair();
        RsaPublicKey publicKey = keyPair.getPublicKey();
        RsaPrivateKey privateKey = keyPair.getPrivateKey();

        BigInteger n = publicKey.getModulus();
        BigInteger e = publicKey.getExponent();
        BigInteger d = privateKey.getExponent();

        System.out.println("n bitLength = " + n.bitLength());
        System.out.println("e = " + e);
        System.out.println("d bitLength = " + d.bitLength());

        // 3. Сервис для файлового RSA
        try (RsaFileCryptoService fileService =
                     new RsaFileCryptoService(nts, 4)) {

            System.out.println();
            System.out.println("===== RSA file encryption demo =====");
            System.out.println("Input file    : " + inputFile.toAbsolutePath());
            System.out.println("Encrypted file: " + encryptedFile.toAbsolutePath());
            System.out.println("Decrypted file: " + decryptedFile.toAbsolutePath());

            // Синхронное шифрование
            System.out.println();
            System.out.println("Шифрование файла RSA...");
            fileService.encryptFile(inputFile, encryptedFile, n, e);
            System.out.println("Готово: " + encryptedFile);

            // Синхронное расшифрование
            System.out.println("Расшифрование файла RSA...");
            fileService.decryptFile(encryptedFile, decryptedFile, n, d);
            System.out.println("Готово: " + decryptedFile);

            byte[] original = Files.readAllBytes(inputFile);
            byte[] decrypted = Files.readAllBytes(decryptedFile);

            System.out.println();
            System.out.println("Сравнение исходного и расшифрованного файлов:");
            System.out.println("Размер оригинала   : " + original.length);
            System.out.println("Размер расшифрован : " + decrypted.length);
            System.out.println("Совпадают побайтно?: " + Arrays.equals(original, decrypted));

            // 4. Асинхронный пример на тех же ключах (по ТЗ "асинхронно и многопоточно")
            System.out.println();
            System.out.println("Асинхронное шифрование и расшифрование (тот же файл)...");

            Path encryptedFile2 = Paths.get("src/main/testdata/input_rsa.enc");
            Path decryptedFile2 = Paths.get("src/main/testdata/input_res.dec.bin");

            Future<Void> encFuture =
                    fileService.encryptFileAsync(inputFile, encryptedFile2, n, e);

            encFuture.get();

            Future<Void> decFuture =
                    fileService.decryptFileAsync(encryptedFile2, decryptedFile2, n, d);

            decFuture.get();

            byte[] original2 = Files.readAllBytes(inputFile);
            byte[] decrypted2 = Files.readAllBytes(decryptedFile2);

            System.out.println("Совпадают побайтно? (async): " +
                    Arrays.equals(original2, decrypted2));

            System.out.println();
            System.out.println("===== RSA file demo finished =====");
        }
    }
}
