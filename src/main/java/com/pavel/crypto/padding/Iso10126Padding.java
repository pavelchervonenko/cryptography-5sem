package com.pavel.crypto.padding;

import com.pavel.crypto.core.Padding;

import java.security.SecureRandom;

public class Iso10126Padding implements Padding {

    private static final SecureRandom RANDOM = new SecureRandom();

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
                    "ISO10126: padCount must be in (0, 255], got " + padCount
            );
        }

        int lastIndex = block.length - 1;

        // Случайные байты для паддинга, кроме последнего.
        for (int i = offset; i < lastIndex; i++) {
            block[i] = (byte) RANDOM.nextInt(256);
        }

        block[lastIndex] = (byte) padCount;

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
        int padCount = block[lastIndex] & 0xFF;

        if (padCount < 1 || padCount > length) {
            throw new IllegalArgumentException(
                    "Invalid ISO 10126 padding value: " + padCount
            );
        }

        // В ISO 10126 все байты паддинга, кроме последнего, могут быть любыми,
        // поэтому их содержимое не проверяем.

        // Количество данных в этом блоке:
        return length - padCount;
    }
}
