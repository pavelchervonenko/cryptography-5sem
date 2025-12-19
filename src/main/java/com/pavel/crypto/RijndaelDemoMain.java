package com.pavel.crypto;

import com.pavel.crypto.gf256.DefaultGf256Service;
import com.pavel.crypto.gf256.Gf256Service;
import com.pavel.crypto.rijndael.RijndaelCipher;

public class RijndaelDemoMain {

    public static void main(String[] args) {
        Gf256Service gf = new DefaultGf256Service();

        // Стандартный AES-модуль: x^8 + x^4 + x^3 + x + 1 => 0x1B
        byte aesMod = (byte) 0x1B;

        byte[] key = hexToBytes("000102030405060708090A0B0C0D0E0F");
        byte[] plain = hexToBytes("00112233445566778899AABBCCDDEEFF");
        byte[] expectedCipher = hexToBytes("69C4E0D86A7B0430D8CDB78070B4C55A");

        RijndaelCipher cipher = new RijndaelCipher(
                128,
                128,
                gf,
                aesMod
        );

        byte[] out = new byte[16];
        cipher.init(true, key);
        cipher.encryptBlock(plain, 0, out, 0);

        System.out.println("AES-128 test:");
        System.out.println("Key      : " + toHex(key));
        System.out.println("Plain    : " + toHex(plain));
        System.out.println("Cipher   : " + toHex(out));
        System.out.println("Expected : " + toHex(expectedCipher));

        byte[] decrypted = new byte[16];
        cipher.init(false, key);
        cipher.decryptBlock(out, 0, decrypted, 0);

        System.out.println("Decrypted: " + toHex(decrypted));
    }

    // ===== вспомогательные методы ДОЛЖНЫ быть вне main, но внутри класса =====

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
