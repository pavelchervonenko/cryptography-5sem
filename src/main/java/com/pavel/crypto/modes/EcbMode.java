package com.pavel.crypto.modes;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;

public class EcbMode implements CipherMode {

    private BlockCipher cipher;
    private int blockSize;
    private boolean forEncryption;

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
        // iv игнорируется в ECB.
    }

    @Override
    public void processBlock(byte[] in, int inOff, byte[] out, int outOff) {
        if (forEncryption) {
            cipher.encryptBlock(in, inOff, out, outOff);
        } else {
            cipher.decryptBlock(in, inOff, out, outOff);
        }
    }
}
