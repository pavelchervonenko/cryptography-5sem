package com.pavel.crypto.padding;

import com.pavel.crypto.core.Padding;

public class NoPadding implements Padding {

    @Override
    public int addPadding(byte[] block, int offset) {
        if (block == null) {
            throw new IllegalArgumentException("block must not be null");
        }

        if (offset < 0 || offset > block.length) {
            throw new IllegalArgumentException("offset out of range");
        }

        // В режиме без паддинга данные в блоке должны занимать весь блок
        if (offset != block.length) {
            throw new IllegalArgumentException(
                    "NoPadding: data length must be equal to block size"
            );
        }

        // Ничего не добавляем
        return 0;
    }

    @Override
    public int removePadding(byte[] block, int offset, int length) {
        if (block == null) {
            throw new IllegalArgumentException("block must not be null");
        }

        if (offset < 0 || length <= 0 || offset + length > block.length) {
            throw new IllegalArgumentException("Invalid offset/length for block");
        }

        // В режиме без паддинга весь блок — данные
        return length;
    }
}
