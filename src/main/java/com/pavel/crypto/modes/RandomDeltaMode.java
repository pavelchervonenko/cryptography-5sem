package com.pavel.crypto.modes;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;

public class RandomDeltaMode implements CipherMode {

    private BlockCipher cipher;
    private int blockSize;
    private boolean forEncryption;

    private byte[] currentValue;
    private long deltaLow64;
    private byte[] tempBlock;

    @Override
    public int getBlockSize() {
        return blockSize;
    }

    @Override
    public void init(boolean forEncryption, BlockCipher cipher, byte[] iv) {
        if (cipher == null) {
            throw new IllegalArgumentException("cipher must not be null");
        }

        if (iv == null) {
            throw new IllegalArgumentException("RandomDelta mode requires IV");
        }

        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.forEncryption = forEncryption;

        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }

        if (blockSize < 8) {
            throw new IllegalArgumentException(
                    "RandomDelta mode requires block size >= 8 bytes"
            );
        }

        this.currentValue = new byte[blockSize];
        this.tempBlock = new byte[blockSize];

        System.arraycopy(iv, 0, this.currentValue, 0, blockSize);

        this.deltaLow64 = extractDeltaFromIv(iv);
    }

    @Override
    public void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (forEncryption) {
            processEncryptBlock(in, inOff, out, outOff);
        } else {
            processDecryptBlock(in, inOff, out, outOff);
        }

        incrementCurrentValue();
    }

    private void processEncryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // X_i = P_i XOR mask_i (mask_i = currentValue)
        for (int i = 0; i < blockSize; i++) {
            int p = in[inOff + i] & 0xFF;
            int mask = currentValue[i] & 0xFF;

            tempBlock[i] = (byte) (p ^ mask);
        }

        // C_i = E_K(X_i)
        cipher.encryptBlock(tempBlock, 0, out, outOff);
    }

    private void processDecryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // X_i = D_K(C_i)
        cipher.decryptBlock(in, inOff, tempBlock, 0);

        // P_i = X_i XOR mask_i (mask_i = currentValue)
        for (int i = 0; i < blockSize; i++) {
            int x = tempBlock[i] & 0xFF;
            int mask = currentValue[i] & 0xFF;

            out[outOff + i] = (byte) (x ^ mask);
        }
    }

    /**
     * Извлечь Delta как 64-битное значение из последних 8 байт IV (big-endian).
     */
    private long extractDeltaFromIv(byte[] iv) {
        int start = blockSize - 8;
        long value = 0L;

        for (int i = start; i < blockSize; i++) {
            int b = iv[i] & 0xFF;
            value = (value << 8) | (long) b;
        }

        return value;
    }

    /**
     * Initial = Initial + Delta (uint128 += uint64 в младших 8 байтах,
     * перенос распространяется в старшие байты при необходимости).
     */
    private void incrementCurrentValue() {
        int lastIndex = blockSize - 1;
        int carry = 0;
        long delta = deltaLow64;

        // Добавляем delta к младшим 8 байтам (big-endian).
        for (int i = 0; i < 8; i++) {
            int index = lastIndex - i;

            int byteValue = currentValue[index] & 0xFF;
            int deltaByte = (int) (delta & 0xFFL);

            int sum = byteValue + deltaByte + carry;

            currentValue[index] = (byte) (sum & 0xFF);

            if (sum >= 256) {
                carry = 1;
            } else {
                carry = 0;
            }

            delta = delta >>> 8;
        }

        // Если остался перенос — проталкиваем его в более старшие байты Initial.
        int index = lastIndex - 8;

        while (carry != 0 && index >= 0) {
            int byteValue = currentValue[index] & 0xFF;

            int sum = byteValue + carry;

            currentValue[index] = (byte) (sum & 0xFF);

            if (sum >= 256) {
                carry = 1;
            } else {
                carry = 0;
            }

            index = index - 1;
        }
    }
}
