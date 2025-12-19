package com.pavel.crypto.core;

public interface BlockCipher {

    int getBlockSize();

    void init(boolean forEncryption, byte[] key);

    void encryptBlock(byte[] in, int inOff, byte[] out, int outOff);

    void decryptBlock(byte[] in, int inOff, byte[] out, int outOff);
}
