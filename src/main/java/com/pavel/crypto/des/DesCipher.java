package com.pavel.crypto.des;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.feistel.FeistelCipher;
import com.pavel.crypto.util.BitPermutation;

// Реализация DES по стандарту FIPS 46-3.
public class DesCipher implements BlockCipher {

    private static final int BLOCK_SIZE = 8;

    // IP (Initial Permutation).
    private static final int[] IP = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9,  1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    // FP (Final Permutation), IP^-1
    private static final int[] FP = {
            40, 8,  48, 16, 56, 24, 64, 32,
            39, 7,  47, 15, 55, 23, 63, 31,
            38, 6,  46, 14, 54, 22, 62, 30,
            37, 5,  45, 13, 53, 21, 61, 29,
            36, 4,  44, 12, 52, 20, 60, 28,
            35, 3,  43, 11, 51, 19, 59, 27,
            34, 2,  42, 10, 50, 18, 58, 26,
            33, 1,  41, 9,  49, 17, 57, 25
    };

    private final FeistelCipher feistelCipher;

    public DesCipher() {
        this.feistelCipher = new FeistelCipher(
                BLOCK_SIZE,
                new DesKeySchedule(),
                new DesRoundFunction()
        );
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        feistelCipher.init(forEncryption, key);
    }

    @Override
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        byte[] block = new byte[BLOCK_SIZE];

        System.arraycopy(in, inOff, block, 0, BLOCK_SIZE);

        byte[] ipBlock = BitPermutation.permuteBytes(block, IP);

        byte[] feistelOut = new byte[BLOCK_SIZE];

        feistelCipher.encryptBlock(ipBlock, 0, feistelOut, 0);

        swapHalves(feistelOut);

        byte[] finalBlock = BitPermutation.permuteBytes(feistelOut, FP);

        System.arraycopy(finalBlock, 0, out, outOff, BLOCK_SIZE);
    }

    @Override
    public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        byte[] block = new byte[BLOCK_SIZE];

        System.arraycopy(in, inOff, block, 0, BLOCK_SIZE);

        byte[] ipBlock = BitPermutation.permuteBytes(block, IP);

        swapHalves(ipBlock);

        byte[] feistelOut = new byte[BLOCK_SIZE];

        feistelCipher.decryptBlock(ipBlock, 0, feistelOut, 0);

        byte[] finalBlock = BitPermutation.permuteBytes(feistelOut, FP);

        System.arraycopy(finalBlock, 0, out, outOff, BLOCK_SIZE);
    }

    // Поменять местами левую и правую половины блока (по 4 байта)
    private void swapHalves(byte[] block) {
        int half = BLOCK_SIZE / 2;

        for (int i = 0; i < half; i++) {
            byte tmp = block[i];
            block[i] = block[half + i];
            block[half + i] = tmp;
        }
    }
}
