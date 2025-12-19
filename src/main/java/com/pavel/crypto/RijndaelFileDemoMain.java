package com.pavel.crypto;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;
import com.pavel.crypto.gf256.DefaultGf256Service;
import com.pavel.crypto.gf256.Gf256Service;
import com.pavel.crypto.modes.CbcMode;
import com.pavel.crypto.padding.Pkcs7Padding;
import com.pavel.crypto.core.Padding;
import com.pavel.crypto.rijndael.RijndaelCipher;
import com.pavel.crypto.symmetric.SymmetricCryptoService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Random;
import java.util.function.Supplier;

public class RijndaelFileDemoMain {

    public static void main(String[] args) throws Exception {
        Path inputFile = Paths.get("src/main/testdata/monkey.jpg");
        Path encryptedFile = Paths.get("src/main/testdata/input.enc");
        Path decryptedFile = Paths.get("src/main/testdata/input.dec.jpg");

        if (!Files.exists(inputFile)) {
            System.out.println("Файл " + inputFile + " не найден. Положи туда какой-нибудь файл.");
            return;
        }

        // 2. Настраиваем Rijndael 128/128 с AES-модулем, CBC + PKCS7
        Gf256Service gf = new DefaultGf256Service();
        byte aesMod = (byte) 0x1B;

        final Gf256Service gfFinal = gf;
        final byte aesModFinal = aesMod;

        Supplier<BlockCipher> cipherSupplier = new Supplier<BlockCipher>() {
            @Override
            public BlockCipher get() {
                return new RijndaelCipher(128, 128, gfFinal, aesModFinal);
            }
        };

        Supplier<CipherMode> modeSupplier = new Supplier<CipherMode>() {
            @Override
            public CipherMode get() {
                return new CbcMode();
            }
        };

        Padding padding = new Pkcs7Padding();

        // Пул на 4 потока — чтобы можно было параллельно шифровать несколько файлов,
        // но здесь мы используем просто синхронно.
        try (SymmetricCryptoService service =
                     new SymmetricCryptoService(cipherSupplier, modeSupplier, padding, 4)) {

            // 3. Генерируем ключ и IV
            byte[] key = new byte[16]; // 128 бит
            byte[] iv = new byte[16];  // 128 бит

            Random rnd = new Random();
            rnd.nextBytes(key);
            rnd.nextBytes(iv);

            System.out.println("===== Rijndael file encryption demo =====");
            System.out.println("Input file : " + inputFile.toAbsolutePath());
            System.out.println("Encrypted  : " + encryptedFile.toAbsolutePath());
            System.out.println("Decrypted  : " + decryptedFile.toAbsolutePath());
            System.out.println("Key (hex)  : " + toHex(key));
            System.out.println("IV  (hex)  : " + toHex(iv));
            System.out.println();

            // 4. Шифруем файл
            System.out.println("Шифрование файла...");
            service.encryptFile(inputFile, encryptedFile, key, iv);
            System.out.println("Готово: " + encryptedFile);

            // 5. Расшифровываем файл
            System.out.println("Расшифрование файла...");
            service.decryptFile(encryptedFile, decryptedFile, key, iv);
            System.out.println("Готово: " + decryptedFile);

            // 6. Сравниваем исходный и расшифрованный
            byte[] originalBytes = Files.readAllBytes(inputFile);
            byte[] decryptedBytes = Files.readAllBytes(decryptedFile);

            boolean same = Arrays.equals(originalBytes, decryptedBytes);

            System.out.println();
            System.out.println("Сравнение исходного и расшифрованного файлов:");
            System.out.println("Размер оригинала   : " + originalBytes.length);
            System.out.println("Размер расшифрован : " + decryptedBytes.length);
            System.out.println("Совпадают побайтно?: " + same);
            System.out.println("===== Demo finished =====");
        }
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);

        int i = 0;
        while (i < data.length) {
            int v = data[i] & 0xFF;

            String hex = Integer.toHexString(v).toUpperCase();

            if (hex.length() < 2) {
                sb.append('0');
            }

            sb.append(hex);
            i = i + 1;
        }

        return sb.toString();
    }
}
