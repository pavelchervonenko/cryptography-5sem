package com.pavel.crypto.des;

import com.pavel.crypto.core.BlockCipher;

// Реализация Triple DES в режиме EDE:
public class TripleDesCipher implements BlockCipher {

    private static final int BLOCK_SIZE = 8;

    private final DesCipher des1;
    private final DesCipher des2;
    private final DesCipher des3;

    public TripleDesCipher() {
        this.des1 = new DesCipher();
        this.des2 = new DesCipher();
        this.des3 = new DesCipher();
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }

    @Override
    public void init(boolean forEncryption, byte[] key) {
        if (key == null) {
            throw new IllegalArgumentException("Key must not be null");
        }

        if (key.length != 16 && key.length != 24) {
            throw new IllegalArgumentException(
                    "Triple DES key must be 16 or 24 bytes long"
            );
        }

        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        byte[] k3 = new byte[8];

        System.arraycopy(key, 0, k1, 0, 8);
        System.arraycopy(key, 8, k2, 0, 8);

        if (key.length == 24) {
            System.arraycopy(key, 16, k3, 0, 8);
        } else {
            System.arraycopy(k1, 0, k3, 0, 8);
        }

        des1.init(true, k1);
        des2.init(true, k2);
        des3.init(true, k3);
    }

    @Override
    public void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        byte[] temp1 = new byte[BLOCK_SIZE];
        byte[] temp2 = new byte[BLOCK_SIZE];

        des1.encryptBlock(in, inOff, temp1, 0);
        des2.decryptBlock(temp1, 0, temp2, 0);
        des3.encryptBlock(temp2, 0, out, outOff);
    }

    @Override
    public void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {
        byte[] temp1 = new byte[BLOCK_SIZE];
        byte[] temp2 = new byte[BLOCK_SIZE];

        des3.decryptBlock(in, inOff, temp1, 0);
        des2.encryptBlock(temp1, 0, temp2, 0);
        des1.decryptBlock(temp2, 0, out, outOff);
    }
}
