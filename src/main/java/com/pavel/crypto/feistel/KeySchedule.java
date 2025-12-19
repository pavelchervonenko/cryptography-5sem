package com.pavel.crypto.feistel;

public interface KeySchedule {

    void init(byte[] key);

    int getRounds();

    byte[] getRoundKey(int round);
}
