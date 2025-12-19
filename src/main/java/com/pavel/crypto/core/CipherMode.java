package com.pavel.crypto.core;

public interface CipherMode {

    int getBlockSize();

    void init(boolean forEncryption, BlockCipher cipher, byte[] iv);

    void processBlock(byte[] in, int inOff, byte[] out, int outOff);
}
