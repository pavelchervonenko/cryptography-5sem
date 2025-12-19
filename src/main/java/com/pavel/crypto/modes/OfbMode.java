package com.pavel.crypto.modes;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;

public class OfbMode implements CipherMode {

    private BlockCipher cipher;
    private int blockSize;

    private byte[] feedback;
    private byte[] outputBlock;

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
            throw new IllegalArgumentException("OFB mode requires IV");
        }

        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();

        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }

        this.feedback = new byte[blockSize];
        this.outputBlock = new byte[blockSize];

        System.arraycopy(iv, 0, this.feedback, 0, blockSize);
    }

    @Override
    public void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // O_i = E_K(O_{i-1})
        cipher.encryptBlock(feedback, 0, outputBlock, 0);

        // C_i / P_i = in XOR O_i (симметрично)
        for (int i = 0; i < blockSize; i++) {
            int value = (in[inOff + i] & 0xFF) ^ (outputBlock[i] & 0xFF);
            out[outOff + i] = (byte) value;
        }

        // feedback = O_i
        for (int i = 0; i < blockSize; i++) {
            feedback[i] = outputBlock[i];
        }
    }
}
