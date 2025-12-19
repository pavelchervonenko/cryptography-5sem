package com.pavel.crypto.feistel;

public interface RoundFunction {

    byte[] apply(byte[] halfBlock, byte[] roundKey);
}
