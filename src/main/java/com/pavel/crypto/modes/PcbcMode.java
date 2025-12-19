package com.pavel.crypto.modes;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;

public class PcbcMode implements CipherMode {

    private BlockCipher cipher;
    private int blockSize;
    private boolean forEncryption;

    private byte[] previousPlain;
    private byte[] previousCipher;
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
            throw new IllegalArgumentException("PCBC mode requires IV");
        }

        this.cipher = cipher;
        this.blockSize = cipher.getBlockSize();
        this.forEncryption = forEncryption;

        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }

        this.previousPlain = new byte[blockSize];
        this.previousCipher = new byte[blockSize];
        this.tempBlock = new byte[blockSize];

        // m_0 = 0, c_0 = IV
        System.arraycopy(iv, 0, this.previousCipher, 0, blockSize);
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
        // temp = m_i XOR m_{i-1} XOR c_{i-1}
        for (int i = 0; i < blockSize; i++) {
            int currentPlain = in[inOff + i] & 0xFF;
            int prevPlainValue = previousPlain[i] & 0xFF;
            int prevCipherValue = previousCipher[i] & 0xFF;

            int value = currentPlain ^ prevPlainValue ^ prevCipherValue;

            tempBlock[i] = (byte) value;
        }

        // c_i = E_k(temp)
        cipher.encryptBlock(tempBlock, 0, out, outOff);

        // обновляем m_{i-1}, c_{i-1}
        for (int i = 0; i < blockSize; i++) {
            previousPlain[i] = in[inOff + i];
            previousCipher[i] = out[outOff + i];
        }
    }

    private void processDecryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // temp = D_k(c_i)
        cipher.decryptBlock(in, inOff, tempBlock, 0);

        // m_i = temp XOR m_{i-1} XOR c_{i-1}
        for (int i = 0; i < blockSize; i++) {
            int tempValue = tempBlock[i] & 0xFF;
            int prevPlainValue = previousPlain[i] & 0xFF;
            int prevCipherValue = previousCipher[i] & 0xFF;

            int value = tempValue ^ prevPlainValue ^ prevCipherValue;

            out[outOff + i] = (byte) value;
        }

        // обновляем m_{i-1}, c_{i-1}
        for (int i = 0; i < blockSize; i++) {
            previousPlain[i] = out[outOff + i];
            previousCipher[i] = in[inOff + i];
        }
    }
}
