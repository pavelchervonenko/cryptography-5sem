package com.pavel.crypto.padding;

import com.pavel.crypto.core.Padding;

public class ZerosPadding implements Padding {

    @Override
    public int addPadding(byte[] block, int offset) {
        if (block == null) {
            throw new IllegalArgumentException("block must not be null");
        }

        if (offset < 0 || offset > block.length) {
            throw new IllegalArgumentException("offset out of range");
        }

        int padCount = block.length - offset;

        if (padCount <= 0) {
            throw new IllegalArgumentException(
                    "ZerosPadding: padCount must be positive " +
                            "(для полного блока нужен отдельный блок с паддингом)"
            );
        }

        for (int i = offset; i < block.length; i++) {
            block[i] = 0;
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

        int end = offset + length - 1;
        int padCount = 0;

        // считаем нули с конца блока [offset, offset+length)
        while (end >= offset && block[end] == 0) {
            padCount = padCount + 1;
            end = end - 1;
        }

        // реальный размер данных в этом блоке
        return length - padCount;
    }
}
