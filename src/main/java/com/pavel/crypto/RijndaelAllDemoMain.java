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

import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Future;
import java.util.function.Supplier;

public class RijndaelAllDemoMain {

    public static void main(String[] args) throws Exception {
        Gf256Service gf = new DefaultGf256Service();
        byte aesMod = (byte) 0x1B;

        System.out.println("===== Rijndael / AES self-test =====");

        // 1. AES-128 официальный тест-вектор
        System.out.println();
        System.out.println("1) AES-128 NIST test vector:");

        byte[] key128 = hexToBytes("000102030405060708090A0B0C0D0E0F");
        byte[] plain128 = hexToBytes("00112233445566778899AABBCCDDEEFF");
        byte[] expectedCipher128 = hexToBytes("69C4E0D86A7B0430D8CDB78070B4C55A");

        RijndaelCipher aes128 = new RijndaelCipher(
                128,
                128,
                gf,
                aesMod
        );
        aes128.init(true, key128);

        byte[] cipherOut = new byte[16];
        aes128.encryptBlock(plain128, 0, cipherOut, 0);

        System.out.println("Key      : " + toHex(key128));
        System.out.println("Plain    : " + toHex(plain128));
        System.out.println("Cipher   : " + toHex(cipherOut));
        System.out.println("Expected : " + toHex(expectedCipher128));
        System.out.println("Match?   : " + Arrays.equals(cipherOut, expectedCipher128));

        byte[] decrypted = new byte[16];
        aes128.init(false, key128);
        aes128.decryptBlock(cipherOut, 0, decrypted, 0);

        System.out.println("Decrypted: " + toHex(decrypted));
        System.out.println("Decrypt OK? " + Arrays.equals(decrypted, plain128));

        // 2. Самосогласованность для всех комбинаций blockSize / keySize
        System.out.println();
        System.out.println("2) Rijndael self-consistency for block/key sizes 128/192/256:");

        int[] blockSizes = new int[]{128, 192, 256};
        int[] keySizes = new int[]{128, 192, 256};

        Random rnd = new Random(12345);

        int bi = 0;
        while (bi < blockSizes.length) {
            int blockBits = blockSizes[bi];
            int bj = 0;
            while (bj < keySizes.length) {
                int keyBits = keySizes[bj];

                int blockBytes = blockBits / 8;
                int keyBytes = keyBits / 8;

                byte[] key = new byte[keyBytes];
                byte[] plain = new byte[blockBytes];

                rnd.nextBytes(key);
                rnd.nextBytes(plain);

                RijndaelCipher rc = new RijndaelCipher(
                        blockBits,
                        keyBits,
                        gf,
                        aesMod
                );
                rc.init(true, key);

                byte[] c = new byte[blockBytes];
                rc.encryptBlock(plain, 0, c, 0);

                byte[] p2 = new byte[blockBytes];
                rc.init(false, key);
                rc.decryptBlock(c, 0, p2, 0);

                boolean ok = Arrays.equals(plain, p2);

                System.out.println("  Block " + blockBits
                        + " bits, Key " + keyBits + " bits: "
                        + (ok ? "OK" : "FAIL"));

                bj = bj + 1;
            }
            bi = bi + 1;
        }

        // 3. Проверка SymmetricCryptoService с Rijndael (CBC + PKCS7)
        System.out.println();
        System.out.println("3) SymmetricCryptoService test (CBC + PKCS7, AES modulus):");

        final Gf256Service gfFinal = gf;
        final byte aesModFinal = aesMod;

        Supplier<BlockCipher> cipherSupplier128 = new Supplier<BlockCipher>() {
            @Override
            public BlockCipher get() {
                return new RijndaelCipher(128, 128, gfFinal, aesModFinal);
            }
        };

        Supplier<CipherMode> cbcModeSupplier = new Supplier<CipherMode>() {
            @Override
            public CipherMode get() {
                return new CbcMode();
            }
        };

        Padding pkcs7 = new Pkcs7Padding();

        // пул потоков на 4 потока
        SymmetricCryptoService service =
                new SymmetricCryptoService(cipherSupplier128, cbcModeSupplier, pkcs7, 4);

        byte[] keyForService = new byte[16];
        byte[] iv = new byte[16];
        rnd.nextBytes(keyForService);
        rnd.nextBytes(iv);

        byte[] data = new byte[1000];
        rnd.nextBytes(data);

        byte[] enc = service.encryptBytes(data, keyForService, iv);
        byte[] dec = service.decryptBytes(enc, keyForService, iv);

        System.out.println("  Random 1000 bytes:");
        System.out.println("  encryptBytes/decryptBytes OK? " + Arrays.equals(data, dec));

        // Асинхронная проверка на паре последовательностей
        byte[] data1 = new byte[5000];
        byte[] data2 = new byte[8000];
        rnd.nextBytes(data1);
        rnd.nextBytes(data2);

        Future<byte[]> f1 = service.encryptBytesAsync(data1, keyForService, iv);
        Future<byte[]> f2 = service.encryptBytesAsync(data2, keyForService, iv);

        byte[] enc1 = f1.get();
        byte[] enc2 = f2.get();

        Future<byte[]> f1d = service.decryptBytesAsync(enc1, keyForService, iv);
        Future<byte[]> f2d = service.decryptBytesAsync(enc2, keyForService, iv);

        byte[] dec1 = f1d.get();
        byte[] dec2 = f2d.get();

        System.out.println("  Async encrypt/decrypt #1 OK? " + Arrays.equals(data1, dec1));
        System.out.println("  Async encrypt/decrypt #2 OK? " + Arrays.equals(data2, dec2));

        // 4. Проверка работы с другим неприводимым модулем
        System.out.println();
        System.out.println("4) Rijndael with different irreducible polynomial:");

        List<Byte> irreducibles = gf.listIrreducibleDegree8();
        System.out.println("  Irreducible polynomials count (degree 8): " + irreducibles.size());

        byte otherMod = aesMod;

        int k = 0;
        while (k < irreducibles.size()) {
            byte candidate = irreducibles.get(k);
            if ((candidate & 0xFF) != (aesMod & 0xFF)) {
                otherMod = candidate;
                break;
            }
            k = k + 1;
        }

        System.out.printf("  AES modulus:    0x%02X%n", aesMod & 0xFF);
        System.out.printf("  Other modulus:  0x%02X%n", otherMod & 0xFF);

        final byte otherModFinal = otherMod;

        Supplier<BlockCipher> cipherSupplier128Other = new Supplier<BlockCipher>() {
            @Override
            public BlockCipher get() {
                return new RijndaelCipher(128, 128, gfFinal, otherModFinal);
            }
        };

        SymmetricCryptoService serviceOther =
                new SymmetricCryptoService(cipherSupplier128Other, cbcModeSupplier, pkcs7, 2);

        byte[] keyOther = new byte[16];
        byte[] ivOther = new byte[16];
        rnd.nextBytes(keyOther);
        rnd.nextBytes(ivOther);

        byte[] dataOther = new byte[1234];
        rnd.nextBytes(dataOther);

        byte[] encOther = serviceOther.encryptBytes(dataOther, keyOther, ivOther);
        byte[] decOther = serviceOther.decryptBytes(encOther, keyOther, ivOther);

        System.out.println("  encrypt/decrypt with other modulus OK? " +
                Arrays.equals(dataOther, decOther));

        service.close();
        serviceOther.close();

        System.out.println();
        System.out.println("===== Rijndael / AES self-test finished =====");
    }

    // ===== Вспомогательные методы =====

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();

        if (len % 2 != 0) {
            throw new IllegalArgumentException("hex length must be even");
        }

        byte[] result = new byte[len / 2];

        int i = 0;
        while (i < len) {
            int hi = fromHexChar(hex.charAt(i));
            int lo = fromHexChar(hex.charAt(i + 1));

            result[i / 2] = (byte) ((hi << 4) | lo);
            i = i + 2;
        }

        return result;
    }

    private static int fromHexChar(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }

        if (c >= 'A' && c <= 'F') {
            return 10 + (c - 'A');
        }

        if (c >= 'a' && c <= 'f') {
            return 10 + (c - 'a');
        }

        throw new IllegalArgumentException("Invalid hex char: " + c);
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
