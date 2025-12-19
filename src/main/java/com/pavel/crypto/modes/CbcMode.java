package com.pavel.crypto.modes;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;

public class CbcMode implements CipherMode {

    private BlockCipher cipher;
    private int blockSize;
    private boolean forEncryption;

    private byte[] prevBlock;
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

        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.forEncryption = forEncryption;

        if (iv == null) {
            throw new IllegalArgumentException("CBC mode requires IV");
        }

        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }

        this.prevBlock = new byte[blockSize];
        this.tempBlock = new byte[blockSize];

        System.arraycopy(iv, 0, this.prevBlock, 0, blockSize);
    }

    @Override
    public void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (forEncryption) {
            processEncryptBlock(in, inOff, out, outOff);
        } else {
            processDecryptBlock(in, inOff, out, outOff);
        }
    }

    private void processEncryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // temp = P_i XOR prevBlock
        for (int i = 0; i < blockSize; i++) {
            tempBlock[i] = (byte) (in[inOff + i] ^ prevBlock[i]);
        }

        // C_i = E_K(temp)
        cipher.encryptBlock(tempBlock, 0, out, outOff);

        // prevBlock = C_i
        for (int i = 0; i < blockSize; i++) {
            prevBlock[i] = out[outOff + i];
        }
    }

    private void processDecryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // temp = D_K(C_i)
        cipher.decryptBlock(in, inOff, tempBlock, 0);

        // P_i = temp XOR prevBlock
        for (int i = 0; i < blockSize; i++) {
            out[outOff + i] = (byte) (tempBlock[i] ^ prevBlock[i]);
        }

        // prevBlock = C_i
        for (int i = 0; i < blockSize; i++) {
            prevBlock[i] = in[inOff + i];
        }
    }
}
