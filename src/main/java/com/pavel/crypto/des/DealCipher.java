package com.pavel.crypto.des;

import com.pavel.crypto.core.BlockCipher;

public class DealCipher implements BlockCipher {

    private static final int BLOCK_SIZE_BYTES = 16; // 128 бит

    // Константный DES-ключ R*
    private static final byte[] R_STAR = hexToBytes("0123456789ABCDEF");

    // Константы C1..C4
    private static final byte[] C1 = constant64(0x01);
    private static final byte[] C2 = constant64(0x02);
    private static final byte[] C3 = constant64(0x03);
    private static final byte[] C4 = constant64(0x04);

    private final DesCipher desForKeySchedule = new DesCipher();
    private final DesCipher desCore = new DesCipher();

    private byte[][] roundKeys; // R1..Rr, каждый по 8 байт
    private int rounds;         // 6 или 8

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE_BYTES;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("DEAL key must not be null");
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new IllegalArgumentException("DEAL key length must be 16, 24, or 32 bytes");
        }

        int segments = key.length / 8; // 2, 3 или 4 (K1..Ks)
        if (segments == 2 || segments == 3) {
            this.rounds = 6;
        } else {
            this.rounds = 8;
        }

        byte[][] K = splitTo64BitBlocks(key, segments);

        this.roundKeys = new byte[rounds][8];
        generateRoundKeys(K);
    }

    @Override
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        checkBlockBounds(in, inOff);
        checkBlockBounds(out, outOff);

        byte[] x = new byte[8]; // левая половина
        byte[] y = new byte[8]; // правая половина
        System.arraycopy(in, inOff, x, 0, 8);
        System.arraycopy(in, inOff + 8, y, 0, 8);

        byte[] temp = new byte[8];

        for (int i = 0; i < rounds; i++) {
            byte[] Ri = roundKeys[i];

            if (i % 2 == 0) {
                // y = y ⊕ E_{Ri}(x)
                desCore.init(true, Ri);
                desCore.encryptBlock(x, 0, temp, 0);
                xorInPlace(y, temp);
            } else {
                // x = x ⊕ E_{Ri}(y)
                desCore.init(true, Ri);
                desCore.encryptBlock(y, 0, temp, 0);
                xorInPlace(x, temp);
            }
        }

        System.arraycopy(x, 0, out, outOff, 8);
        System.arraycopy(y, 0, out, outOff + 8, 8);
    }

    @Override
    public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        checkBlockBounds(in, inOff);
        checkBlockBounds(out, outOff);

        byte[] x = new byte[8];
        byte[] y = new byte[8];
        System.arraycopy(in, inOff, x, 0, 8);
        System.arraycopy(in, inOff + 8, y, 0, 8);

        byte[] temp = new byte[8];

        // Обратное преобразование:
        for (int i = rounds - 1; i >= 0; i--) {
            byte[] Ri = roundKeys[i];

            if (i % 2 == 0) {
                // инверсия y = y XOR E_{Ri}(x)
                desCore.init(true, Ri);
                desCore.encryptBlock(x, 0, temp, 0);
                xorInPlace(y, temp);
            } else {
                // инверсия x = x XOR E_{Ri}(y)
                desCore.init(true, Ri);
                desCore.encryptBlock(y, 0, temp, 0);
                xorInPlace(x, temp);
            }
        }

        System.arraycopy(x, 0, out, outOff, 8);
        System.arraycopy(y, 0, out, outOff + 8, 8);
    }

    private static void checkBlockBounds(byte[] buf, int off) {
        if (buf == null) {
            throw new IllegalArgumentException("Buffer is null");
        }
        if (off < 0 || off + BLOCK_SIZE_BYTES > buf.length) {
            throw new IllegalArgumentException("Invalid offset for 16-byte block");
        }
    }

    private static byte[][] splitTo64BitBlocks(byte[] key, int segments) {
        byte[][] result = new byte[segments][8];
        for (int i = 0; i < segments; i++) {
            System.arraycopy(key, i * 8, result[i], 0, 8);
        }
        return result; // K1..Ks
    }

    private void generateRoundKeys(byte[][] K) {
        desForKeySchedule.init(true, R_STAR);

        byte[] tmp = new byte[8];
        byte[] buf = new byte[8];

        int s = K.length;

        if (s == 2) {
            // DEAL-128: K[0] = K1, K[1] = K2
            // R1
            desForKeySchedule.encryptBlock(K[0], 0, roundKeys[0], 0);

            // R2
            xor(buf, K[1], roundKeys[0]);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[1], 0);

            // R3
            xor3(buf, K[0], roundKeys[1], C1);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[2], 0);

            // R4
            xor3(buf, K[1], roundKeys[2], C2);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[3], 0);

            // R5
            xor3(buf, K[0], roundKeys[3], C3);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[4], 0);

            // R6
            xor3(buf, K[1], roundKeys[4], C4);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[5], 0);

        } else if (s == 3) {
            // DEAL-192: K[0] = K1, K[1] = K2, K[2] = K3

            // R1
            desForKeySchedule.encryptBlock(K[0], 0, roundKeys[0], 0);

            // R2
            xor(buf, K[1], roundKeys[0]);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[1], 0);

            // R3
            xor(buf, K[2], roundKeys[1]);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[2], 0);

            // R4
            xor3(buf, K[0], roundKeys[2], C1);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[3], 0);

            // R5
            xor3(buf, K[1], roundKeys[3], C2);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[4], 0);

            // R6
            xor3(buf, K[2], roundKeys[4], C3);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[5], 0);

        } else if (s == 4) {
            // DEAL-256: K[0]=K1, ..., K[3]=K4

            // R1
            desForKeySchedule.encryptBlock(K[0], 0, roundKeys[0], 0);

            // R2
            xor(buf, K[1], roundKeys[0]);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[1], 0);

            // R3
            xor(buf, K[2], roundKeys[1]);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[2], 0);

            // R4
            xor(buf, K[3], roundKeys[2]);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[3], 0);

            // R5
            xor3(buf, K[0], roundKeys[3], C1);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[4], 0);

            // R6
            xor3(buf, K[1], roundKeys[4], C2);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[5], 0);

            // R7
            xor3(buf, K[2], roundKeys[5], C3);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[6], 0);

            // R8
            xor3(buf, K[3], roundKeys[6], C4);
            desForKeySchedule.encryptBlock(buf, 0, roundKeys[7], 0);
        } else {
            throw new IllegalStateException("Unexpected number of 64-bit segments: " + s);
        }
    }

    private static void xorInPlace(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            a[i] = (byte) (a[i] ^ b[i]);
        }
    }

    private static void xor(byte[] out, byte[] a, byte[] b) {
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
    }

    private static void xor3(byte[] out, byte[] a, byte[] b, byte[] c) {
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (a[i] ^ b[i] ^ c[i]);
        }
    }

    private static byte[] constant64(int lastByte) {
        byte[] c = new byte[8];
        c[7] = (byte) lastByte;
        return c;
    }

    private static byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string length must be even");
        }
        int len = hex.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            int hi = Character.digit(hex.charAt(2 * i), 16);
            int lo = Character.digit(hex.charAt(2 * i + 1), 16);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
