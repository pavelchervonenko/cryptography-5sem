package com.pavel.crypto.modes;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;

public class CtrMode implements CipherMode {

    private BlockCipher cipher;
    private int blockSize;

    private byte[] counter;
    private byte[] keystreamBlock;

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

        if (iv == null) {
            throw new IllegalArgumentException("CTR mode requires IV (initial counter)");
        }

        if (iv.length != blockSize) {
            throw new IllegalArgumentException("IV length must equal block size");
        }

        this.counter = new byte[blockSize];
        this.keystreamBlock = new byte[blockSize];

        System.arraycopy(iv, 0, this.counter, 0, blockSize);
    }

    @Override
    public void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        // keystreamBlock = E_K(counter)
        cipher.encryptBlock(counter, 0, keystreamBlock, 0);

        // out = in XOR keystreamBlock
        for (int i = 0; i < blockSize; i++) {
            out[outOff + i] = (byte) (in[inOff + i] ^ keystreamBlock[i]);
        }

        incrementCounter();
    }

    /**
     * Увеличить счётчик на 1 (big-endian).
     */
    private void incrementCounter() {
        for (int i = blockSize - 1; i >= 0; i--) {
            int value = (counter[i] & 0xFF) + 1;
            counter[i] = (byte) value;

            if ((value & 0x100) == 0) {
                break;
            }
        }
    }
}
