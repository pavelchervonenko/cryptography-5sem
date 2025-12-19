package com.pavel.crypto.modes;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;

public class CfbMode implements CipherMode {

    private BlockCipher cipher;
    private int blockSize;
    private boolean forEncryption;

    private byte[] feedback;
    private byte[] keystream;

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
            throw new IllegalArgumentException("CFB mode requires IV");
        }

        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.forEncryption = forEncryption;

        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }

        this.feedback = new byte[blockSize];
        this.keystream = new byte[blockSize];

        System.arraycopy(iv, 0, this.feedback, 0, blockSize);
    }

    @Override
    public void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // keystream = E_K(feedback)
        cipher.encryptBlock(feedback, 0, keystream, 0);

        if (forEncryption) {
            // C_i = keystream XOR P_i
            for (int i = 0; i < blockSize; i++) {
                int ks = keystream[i] & 0xFF;
                int p = in[inOff + i] & 0xFF;

                out[outOff + i] = (byte) (ks ^ p);
            }

            // feedback = C_i
            for (int i = 0; i < blockSize; i++) {
                feedback[i] = out[outOff + i];
            }
        } else {
            // P_i = keystream XOR C_i
            for (int i = 0; i < blockSize; i++) {
                int ks = keystream[i] & 0xFF;
                int c = in[inOff + i] & 0xFF;

                out[outOff + i] = (byte) (ks ^ c);
            }

            // feedback = C_i
            for (int i = 0; i < blockSize; i++) {
                feedback[i] = in[inOff + i];
            }
        }
    }
}
