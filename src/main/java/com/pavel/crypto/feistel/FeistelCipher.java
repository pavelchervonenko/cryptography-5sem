package com.pavel.crypto.feistel;

import com.pavel.crypto.core.BlockCipher;

public class FeistelCipher implements BlockCipher {

    private final int blockSizeBytes;
    private final KeySchedule keySchedule;
    private final RoundFunction roundFunction;

    public FeistelCipher(int blockSizeBytes,
                         KeySchedule keySchedule,
                         RoundFunction roundFunction) {
        this.blockSizeBytes = blockSizeBytes;
        this.keySchedule = keySchedule;
        this.roundFunction = roundFunction;
    }

    @Override
    public int getBlockSize() {
        return blockSizeBytes;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        keySchedule.init(key);
    }

    @Override
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        processBlock(in, inOff, out, outOff, true);
    }

    @Override
    public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        processBlock(in, inOff, out, outOff, false);
    }

    private void processBlock(byte[] in,
                              int inOff,
                              byte[] out,
                              int outOff,
                              boolean encrypt) {

        int halfSize = blockSizeBytes / 2;

        byte[] left = new byte[halfSize];
        byte[] right = new byte[halfSize];

        System.arraycopy(in, inOff, left, 0, halfSize);
        System.arraycopy(in, inOff + halfSize, right, 0, halfSize);

        int rounds = keySchedule.getRounds();

        if (encrypt) {
            for (int round = 0; round < rounds; round++) {
                byte[] roundKey = keySchedule.getRoundKey(round);

                byte[] f = roundFunction.apply(right, roundKey);

                byte[] newRight = xorArrays(left, f);
                byte[] newLeft = right;

                left = newLeft;
                right = newRight;
            }
        } else {
            for (int round = rounds - 1; round >= 0; round--) {
                byte[] roundKey = keySchedule.getRoundKey(round);

                byte[] f = roundFunction.apply(left, roundKey);

                byte[] newLeft = xorArrays(right, f);
                byte[] newRight = left;

                right = newRight;
                left = newLeft;
            }
        }

        System.arraycopy(left, 0, out, outOff, halfSize);
        System.arraycopy(right, 0, out, outOff + halfSize, halfSize);
    }

    private byte[] xorArrays(byte[] a, byte[] b) {
        int length = a.length;
        byte[] result = new byte[length];

        for (int i = 0; i < length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }

        return result;
    }
}
