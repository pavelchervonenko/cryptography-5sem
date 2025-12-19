package com.pavel.crypto.core;

public interface Padding {

    int addPadding(byte[] block, int offset);

    int removePadding(byte[] block, int offset, int length);
}
