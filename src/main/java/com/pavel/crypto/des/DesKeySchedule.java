package com.pavel.crypto.des;

import com.pavel.crypto.feistel.KeySchedule;
import com.pavel.crypto.util.BitPermutation;

// Реализация расписания ключей DES по стандарту FIPS 46-3
public class DesKeySchedule implements KeySchedule {

    private static final int ROUNDS = 16;

    // PC-1
    private static final int[] PC1 = {
            57, 49, 41, 33, 25, 17, 9,
            1,  58, 50, 42, 34, 26, 18,
            10, 2,  59, 51, 43, 35, 27,
            19, 11, 3,  60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7,  62, 54, 46, 38, 30, 22,
            14, 6,  61, 53, 45, 37, 29,
            21, 13, 5,  28, 20, 12, 4
    };

    // PC-2
    private static final int[] PC2 = {
            14, 17, 11, 24, 1,  5,
            3,  28, 15, 6,  21, 10,
            23, 19, 12, 4,  26, 8,
            16, 7,  27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    // График циклических сдвигов C и D:
    private static final int[] SHIFTS = {
            1, 1, 2, 2,
            2, 2, 2, 2,
            1, 2, 2, 2,
            2, 2, 2, 1
    };

    private final byte[][] subkeys = new byte[ROUNDS][];

    @Override
    public void init(byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }

        if (key.length != 8) {
            throw new IllegalArgumentException("DES key must be 8 bytes (64 bits) long");
        }

        // Применяем PC-1 к 64-битному ключу -> получаем 56 бит (7 байт).
        byte[] key56 = BitPermutation.permuteBytes(key, PC1);

        // Преобразуем 56 бит в одно 56-битное целое (long).
        long key56Value = bytesTo56Bits(key56);

        // Разбиваем на C и D по 28 бит.
        int c = (int) (key56Value >>> 28);
        int d = (int) (key56Value & 0x0FFFFFFFL);

        // 16 раундов.
        for (int round = 0; round < ROUNDS; round++) {
            int shift = SHIFTS[round];

            c = leftRotate28(c, shift);
            d = leftRotate28(d, shift);

            long cd = ((long) c << 28) | (d & 0x0FFFFFFFL);

            byte[] cdBytes = bits56ToBytes(cd);

            byte[] subkey48 = BitPermutation.permuteBytes(cdBytes, PC2);

            subkeys[round] = subkey48;
        }
    }

    @Override
    public int getRounds() {
        return ROUNDS;
    }

    @Override
    public byte[] getRoundKey(int round) {
        if (round < 0 || round >= ROUNDS) {
            throw new IllegalArgumentException("Round index out of range: " + round);
        }

        byte[] original = subkeys[round];
        byte[] copy = new byte[original.length];

        System.arraycopy(original, 0, copy, 0, original.length);

        return copy;
    }

    private long bytesTo56Bits(byte[] key56) {
        if (key56.length != 7) {
            throw new IllegalArgumentException("Expected 7 bytes for 56-bit value");
        }

        long result = 0L;

        for (int i = 0; i < 7; i++) {
            int b = key56[i] & 0xFF;
            result = (result << 8) | b;
        }

        return result;
    }

    private byte[] bits56ToBytes(long value) {
        byte[] bytes = new byte[7];

        for (int i = 6; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFFL);
            value = value >>> 8;
        }

        return bytes;
    }

    private int leftRotate28(int value, int shift) {
        int masked = value & 0x0FFFFFFF;

        int left = (masked << shift) & 0x0FFFFFFF;
        int right = masked >>> (28 - shift);

        return left | right;
    }
}
