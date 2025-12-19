package com.pavel.crypto.rijndael;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.gf256.Gf256Service;

public class RijndaelCipher implements BlockCipher {

    private final int blockSizeBits;
    private final int keySizeBits;
    private final int Nb; // число 32-битных слов в блоке
    private final int Nk; // число 32-битных слов в ключе
    private final int Nr; // число раундов

    private final int blockSizeBytes;

    private final Gf256Service gf;
    private final byte modulus;

    private final byte[] sBox = new byte[256];
    private final byte[] invSBox = new byte[256];

    private boolean forEncryption;
    private int[] roundKeys; // заполняется в init(...)

    public RijndaelCipher(int blockSizeBits,
                          int keySizeBits,
                          Gf256Service gf,
                          byte modulus) {
        if (gf == null) {
            throw new IllegalArgumentException("gf must not be null");
        }

        this.gf = gf;
        this.modulus = modulus;

        if (blockSizeBits != 128
                && blockSizeBits != 192
                && blockSizeBits != 256) {
            throw new IllegalArgumentException("Unsupported block size: " + blockSizeBits);
        }

        if (keySizeBits != 128
                && keySizeBits != 192
                && keySizeBits != 256) {
            throw new IllegalArgumentException("Unsupported key size: " + keySizeBits);
        }

        this.blockSizeBits = blockSizeBits;
        this.keySizeBits = keySizeBits;

        this.Nb = blockSizeBits / 32;
        this.Nk = keySizeBits / 32;
        this.Nr = Math.max(Nb, Nk) + 6;

        this.blockSizeBytes = 4 * Nb;

        generateSBoxes();
    }

    @Override
    public int getBlockSize() {
        return blockSizeBytes;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }

        if (key.length * 8 != keySizeBits) {
            throw new IllegalArgumentException(
                    "Key length in bits (" + (key.length * 8) +
                            ") does not match expected keySizeBits " + keySizeBits
            );
        }

        this.forEncryption = forEncryption;
        this.roundKeys = expandKey(key);
    }

    @Override
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (!forEncryption) {
        }

        if (roundKeys == null) {
            throw new IllegalStateException("Cipher is not initialized");
        }

        if (in == null || out == null) {
            throw new IllegalArgumentException("in/out must not be null");
        }

        if (inOff < 0 || outOff < 0
                || inOff + blockSizeBytes > in.length
                || outOff + blockSizeBytes > out.length) {
            throw new IllegalArgumentException("Invalid offset for encryptBlock");
        }

        byte[] state = new byte[blockSizeBytes];

        System.arraycopy(in, inOff, state, 0, blockSizeBytes);

        addRoundKey(state, 0);

        int round = 1;
        while (round < Nr) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, round);
            round = round + 1;
        }

        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Nr);

        System.arraycopy(state, 0, out, outOff, blockSizeBytes);
    }

    @Override
    public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (forEncryption) {
        }

        if (roundKeys == null) {
            throw new IllegalStateException("Cipher is not initialized");
        }

        if (in == null || out == null) {
            throw new IllegalArgumentException("in/out must not be null");
        }

        if (inOff < 0 || outOff < 0
                || inOff + blockSizeBytes > in.length
                || outOff + blockSizeBytes > out.length) {
            throw new IllegalArgumentException("Invalid offset for decryptBlock");
        }

        byte[] state = new byte[blockSizeBytes];

        System.arraycopy(in, inOff, state, 0, blockSizeBytes);

        addRoundKey(state, Nr);

        int round = Nr - 1;
        while (round > 0) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            invMixColumns(state);
            round = round - 1;
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);

        System.arraycopy(state, 0, out, outOff, blockSizeBytes);
    }

    // S-box и Inv S-box

    private void generateSBoxes() {
        for (int i = 0; i < 256; i++) {
            byte x = (byte) i;
            byte inv;

            if (x == 0) {
                inv = 0;
            } else {
                inv = gf.inverse(x, modulus);
            }

            sBox[i] = affineTransform(inv);
        }

        for (int i = 0; i < 256; i++) {
            invSBox[i] = 0;
        }

        for (int x = 0; x < 256; x++) {
            int y = sBox[x] & 0xFF;
            invSBox[y] = (byte) x;
        }
    }

    private byte affineTransform(byte x) {
        int a = x & 0xFF;
        int b = 0;

        int i = 0;
        while (i < 8) {
            int bit =
                    ((a >>> i) & 1)
                            ^ ((a >>> ((i + 4) & 7)) & 1)
                            ^ ((a >>> ((i + 5) & 7)) & 1)
                            ^ ((a >>> ((i + 6) & 7)) & 1)
                            ^ ((a >>> ((i + 7) & 7)) & 1);

            b = b | (bit << i);
            i = i + 1;
        }

        b = b ^ 0x63;

        return (byte) b;
    }

    // Key schedule

    private int[] expandKey(byte[] key) {
        int wordsCount = Nb * (Nr + 1);
        int[] w = new int[wordsCount];

        int i = 0;
        while (i < Nk) {
            int b0 = key[4 * i] & 0xFF;
            int b1 = key[4 * i + 1] & 0xFF;
            int b2 = key[4 * i + 2] & 0xFF;
            int b3 = key[4 * i + 3] & 0xFF;

            int word = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

            w[i] = word;
            i = i + 1;
        }

        int rcon = 0x01;

        while (i < wordsCount) {
            int temp = w[i - 1];

            if (i % Nk == 0) {
                temp = subWord(rotWord(temp));

                temp = ((temp >>> 24) ^ (rcon & 0xFF)) << 24
                        | (temp & 0x00FFFFFF);

                rcon = gf.multiply((byte) rcon, (byte) 0x02, modulus) & 0xFF;
            } else if (Nk > 6 && (i % Nk) == 4) {
                temp = subWord(temp);
            }

            w[i] = w[i - Nk] ^ temp;
            i = i + 1;
        }

        return w;
    }

    private int rotWord(int word) {
        int b0 = (word >>> 24) & 0xFF;
        int rest = (word << 8) & 0xFFFFFF00;
        return rest | b0;
    }

    private int subWord(int word) {
        int b0 = (word >>> 24) & 0xFF;
        int b1 = (word >>> 16) & 0xFF;
        int b2 = (word >>> 8) & 0xFF;
        int b3 = word & 0xFF;

        b0 = sBox[b0] & 0xFF;
        b1 = sBox[b1] & 0xFF;
        b2 = sBox[b2] & 0xFF;
        b3 = sBox[b3] & 0xFF;

        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    // Раундовые преобразования

    private void addRoundKey(byte[] state, int round) {
        int offset = round * Nb;

        for (int col = 0; col < Nb; col++) {
            int word = roundKeys[offset + col];

            int s0Index = 4 * col;
            int s1Index = s0Index + 1;
            int s2Index = s0Index + 2;
            int s3Index = s0Index + 3;

            state[s0Index] = (byte) (state[s0Index] ^ ((word >>> 24) & 0xFF));
            state[s1Index] = (byte) (state[s1Index] ^ ((word >>> 16) & 0xFF));
            state[s2Index] = (byte) (state[s2Index] ^ ((word >>> 8) & 0xFF));
            state[s3Index] = (byte) (state[s3Index] ^ (word & 0xFF));
        }
    }

    private void subBytes(byte[] state) {
        int i = 0;
        while (i < state.length) {
            int value = state[i] & 0xFF;
            state[i] = sBox[value];
            i = i + 1;
        }
    }

    private void invSubBytes(byte[] state) {
        int i = 0;
        while (i < state.length) {
            int value = state[i] & 0xFF;
            state[i] = invSBox[value];
            i = i + 1;
        }
    }

    private void shiftRows(byte[] state) {
        shiftRow(state, 1, 1);
        shiftRow(state, 2, 2);
        shiftRow(state, 3, 3);
    }

    private void invShiftRows(byte[] state) {
        shiftRow(state, 1, Nb - 1);
        shiftRow(state, 2, Nb - 2);
        shiftRow(state, 3, Nb - 3);
    }

    private void shiftRow(byte[] state, int row, int shift) {
        shift = shift % Nb;

        if (shift == 0) {
            return;
        }

        byte[] temp = new byte[Nb];

        int c = 0;
        while (c < Nb) {
            int srcCol = (c + shift) % Nb;
            temp[c] = state[row + 4 * srcCol];
            c = c + 1;
        }

        c = 0;
        while (c < Nb) {
            state[row + 4 * c] = temp[c];
            c = c + 1;
        }
    }

    private void mixColumns(byte[] state) {
        int col = 0;

        while (col < Nb) {
            int index = 4 * col;

            byte s0 = state[index];
            byte s1 = state[index + 1];
            byte s2 = state[index + 2];
            byte s3 = state[index + 3];

            byte s0_2 = gf.multiply(s0, (byte) 0x02, modulus);
            byte s1_2 = gf.multiply(s1, (byte) 0x02, modulus);
            byte s2_2 = gf.multiply(s2, (byte) 0x02, modulus);
            byte s3_2 = gf.multiply(s3, (byte) 0x02, modulus);

            byte s0_3 = (byte) (s0_2 ^ s0);
            byte s1_3 = (byte) (s1_2 ^ s1);
            byte s2_3 = (byte) (s2_2 ^ s2);
            byte s3_3 = (byte) (s3_2 ^ s3);

            byte r0 = (byte) (s0_2 ^ s1_3 ^ s2 ^ s3);
            byte r1 = (byte) (s0 ^ s1_2 ^ s2_3 ^ s3);
            byte r2 = (byte) (s0 ^ s1 ^ s2_2 ^ s3_3);
            byte r3 = (byte) (s0_3 ^ s1 ^ s2 ^ s3_2);

            state[index] = r0;
            state[index + 1] = r1;
            state[index + 2] = r2;
            state[index + 3] = r3;

            col = col + 1;
        }
    }

    private void invMixColumns(byte[] state) {
        int col = 0;

        while (col < Nb) {
            int index = 4 * col;

            byte s0 = state[index];
            byte s1 = state[index + 1];
            byte s2 = state[index + 2];
            byte s3 = state[index + 3];

            byte s0_2 = gf.multiply(s0, (byte) 0x02, modulus);
            byte s0_4 = gf.multiply(s0_2, (byte) 0x02, modulus);
            byte s0_8 = gf.multiply(s0_4, (byte) 0x02, modulus);

            byte s1_2 = gf.multiply(s1, (byte) 0x02, modulus);
            byte s1_4 = gf.multiply(s1_2, (byte) 0x02, modulus);
            byte s1_8 = gf.multiply(s1_4, (byte) 0x02, modulus);

            byte s2_2 = gf.multiply(s2, (byte) 0x02, modulus);
            byte s2_4 = gf.multiply(s2_2, (byte) 0x02, modulus);
            byte s2_8 = gf.multiply(s2_4, (byte) 0x02, modulus);

            byte s3_2 = gf.multiply(s3, (byte) 0x02, modulus);
            byte s3_4 = gf.multiply(s3_2, (byte) 0x02, modulus);
            byte s3_8 = gf.multiply(s3_4, (byte) 0x02, modulus);

            byte s0_9 = (byte) (s0_8 ^ s0);
            byte s0_11 = (byte) (s0_8 ^ s0_2 ^ s0);
            byte s0_13 = (byte) (s0_8 ^ s0_4 ^ s0);
            byte s0_14 = (byte) (s0_8 ^ s0_4 ^ s0_2);

            byte s1_9 = (byte) (s1_8 ^ s1);
            byte s1_11 = (byte) (s1_8 ^ s1_2 ^ s1);
            byte s1_13 = (byte) (s1_8 ^ s1_4 ^ s1);
            byte s1_14 = (byte) (s1_8 ^ s1_4 ^ s1_2);

            byte s2_9 = (byte) (s2_8 ^ s2);
            byte s2_11 = (byte) (s2_8 ^ s2_2 ^ s2);
            byte s2_13 = (byte) (s2_8 ^ s2_4 ^ s2);
            byte s2_14 = (byte) (s2_8 ^ s2_4 ^ s2_2);

            byte s3_9 = (byte) (s3_8 ^ s3);
            byte s3_11 = (byte) (s3_8 ^ s3_2 ^ s3);
            byte s3_13 = (byte) (s3_8 ^ s3_4 ^ s3);
            byte s3_14 = (byte) (s3_8 ^ s3_4 ^ s3_2);

            byte r0 = (byte) (s0_14 ^ s1_11 ^ s2_13 ^ s3_9);
            byte r1 = (byte) (s0_9 ^ s1_14 ^ s2_11 ^ s3_13);
            byte r2 = (byte) (s0_13 ^ s1_9 ^ s2_14 ^ s3_11);
            byte r3 = (byte) (s0_11 ^ s1_13 ^ s2_9 ^ s3_14);

            state[index] = r0;
            state[index + 1] = r1;
            state[index + 2] = r2;
            state[index + 3] = r3;

            col = col + 1;
        }
    }
}
