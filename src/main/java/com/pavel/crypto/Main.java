package com.pavel.crypto;

import com.pavel.crypto.des.DealCipher;
import com.pavel.crypto.des.DesCipher;
import com.pavel.crypto.des.TripleDesCipher;

public class Main {

    public static void main(String[] args) {
        String keyHex = "133457799BBCDFF1";
        String plainHex = "0123456789ABCDEF";
        String expectedCipherHex = "85E813540F0AB405";

        byte[] key = hexToBytes(keyHex);
        byte[] plain = hexToBytes(plainHex);

        DesCipher des = new DesCipher();

        // Шифрование
        des.init(true, key);

        byte[] cipher = new byte[8];
        des.encryptBlock(plain, 0, cipher, 0);

        String cipherHex = bytesToHex(cipher);

        System.out.println("DES test:");
        System.out.println("Key      : " + keyHex);
        System.out.println("Plain    : " + plainHex);
        System.out.println("Cipher   : " + cipherHex);
        System.out.println("Expected : " + expectedCipherHex);

        // Расшифрование
        des.init(false, key);

        byte[] decrypted = new byte[8];
        des.decryptBlock(cipher, 0, decrypted, 0);

        String decryptedHex = bytesToHex(decrypted);

        System.out.println("Decrypted: " + decryptedHex);

        // ---- ТЕСТ 3DES ----

        TripleDesCipher tripleDes = new TripleDesCipher();

        // K1 = K2 = K3 = key
        String tripleKeyHex = keyHex + keyHex + keyHex;
        byte[] tripleKey = hexToBytes(tripleKeyHex);

        tripleDes.init(true, tripleKey);

        byte[] tripleCipher = new byte[8];
        tripleDes.encryptBlock(plain, 0, tripleCipher, 0);

        String tripleCipherHex = bytesToHex(tripleCipher);

        System.out.println();
        System.out.println("3DES test (K1=K2=K3=DES key):");
        System.out.println("3DES Key  : " + tripleKeyHex);
        System.out.println("Plain     : " + plainHex);
        System.out.println("3DES Cipher: " + tripleCipherHex);
        System.out.println("Should match DES cipher above");

        tripleDes.init(false, tripleKey);

        byte[] tripleDecrypted = new byte[8];
        tripleDes.decryptBlock(tripleCipher, 0, tripleDecrypted, 0);

        String tripleDecryptedHex = bytesToHex(tripleDecrypted);

        System.out.println("3DES Decrypted: " + tripleDecryptedHex);
    }

    private static byte[] hexToBytes(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex string must not be null");
        }

        int length = hex.length();

        if (length % 2 != 0) {
            throw new IllegalArgumentException("hex string length must be even");
        }

        int byteCount = length / 2;
        byte[] result = new byte[byteCount];

        for (int i = 0; i < byteCount; i++) {
            int high = hexCharToInt(hex.charAt(2 * i));
            int low = hexCharToInt(hex.charAt(2 * i + 1));

            int value = (high << 4) | low;

            result[i] = (byte) value;
        }

        return result;
    }

    private static int hexCharToInt(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }

        if (c >= 'A' && c <= 'F') {
            return 10 + (c - 'A');
        }

        if (c >= 'a' && c <= 'f') {
            return 10 + (c - 'a');
        }

        throw new IllegalArgumentException("Invalid hex character: " + c);
    }

    private static String bytesToHex(byte[] data) {
        if (data == null) {
            return "null";
        }

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < data.length; i++) {
            int value = data[i] & 0xFF;

            String hex = Integer.toHexString(value).toUpperCase();

            if (hex.length() == 1) {
                sb.append('0');
            }

            sb.append(hex);
        }

        return sb.toString();
    }
}
