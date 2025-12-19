package com.pavel.crypto.padding;

import com.pavel.crypto.core.Padding;

public class Pkcs7Padding implements Padding {

    @Override
    public int addPadding(byte[] block, int offset) {
        if (block == null) {
            throw new IllegalArgumentException("block must not be null");
        }

        if (offset < 0 || offset > block.length) {
            throw new IllegalArgumentException("offset out of range");
        }

        int padCount = block.length - offset;

        if (padCount <= 0 || padCount > 255) {
            throw new IllegalArgumentException(
                    "padCount must be in [1, 255], got " + padCount
            );
        }

        byte padValue = (byte) padCount;

        for (int i = offset; i < block.length; i++) {
            block[i] = padValue;
        }

        return padCount;
    }

    @Override
    public int removePadding(byte[] block, int offset, int length) {
        if (block == null) {
            throw new IllegalArgumentException("block must not be null");
        }

        if (offset < 0 || length <= 0 || offset + length > block.length) {
            throw new IllegalArgumentException("Invalid offset/length for block");
        }

        int lastIndex = offset + length - 1;
        int padValue = block[lastIndex] & 0xFF;

        if (padValue < 1 || padValue > length) {
            throw new IllegalArgumentException(
                    "Invalid PKCS7 padding value: " + padValue
            );
        }

        // Проверяем, что последние padValue байт равны padValue
        int startPad = lastIndex - padValue + 1;

        for (int i = startPad; i <= lastIndex; i++) {
            int value = block[i] & 0xFF;

            if (value != padValue) {
                throw new IllegalArgumentException("Invalid PKCS7 padding bytes");
            }
        }

        // Количество данных в блоке = length - padValue
        return length - padValue;
    }
}
