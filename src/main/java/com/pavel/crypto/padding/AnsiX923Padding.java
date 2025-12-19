package com.pavel.crypto.padding;

import com.pavel.crypto.core.Padding;

public class AnsiX923Padding implements Padding {

    @Override
    public int addPadding(byte[] block, int dataLength) {
        if (block == null) {
            throw new IllegalArgumentException("block must not be null");
        }

        if (dataLength < 0 || dataLength > block.length) {
            throw new IllegalArgumentException("dataLength out of range");
        }

        int padCount = block.length - dataLength;

        if (padCount <= 0) {
            throw new IllegalArgumentException(
                    "padCount must be positive (для полного блока нужен отдельный блок паддинга)"
            );
        }

        int lastIndex = block.length - 1;

        for (int i = dataLength; i < lastIndex; i++) {
            block[i] = 0;
        }

        block[lastIndex] = (byte) padCount;

        return padCount;
    }

    /**
     * Удаление паддинга ANSI X9.23.
     *
     * @param data   массив, содержащий блок с паддингом
     * @param offset смещение начала блока в массиве
     * @param length длина блока (обычно размер блока шифра)
     * @return количество байт паддинга
     */
    @Override
    public int removePadding(byte[] data, int offset, int length) {
        if (data == null) {
            throw new IllegalArgumentException("data must not be null");
        }

        if (offset < 0 || length <= 0 || offset + length > data.length) {
            throw new IllegalArgumentException("Invalid offset/length for block");
        }

        int lastIndex = offset + length - 1;

        int padCount = data[lastIndex] & 0xFF;

        if (padCount < 1 || padCount > length) {
            throw new IllegalArgumentException(
                    "Invalid ANSI X9.23 padding value: " + padCount
            );
        }

        int start = lastIndex - padCount + 1;

        // Все байты паддинга, кроме последнего, должны быть 0x00
        for (int i = start; i < lastIndex; i++) {
            if (data[i] != 0) {
                throw new IllegalArgumentException("Invalid ANSI X9.23 padding bytes");
            }
        }

        return padCount;
    }

    // Если где-то в коде ещё используется getPadCount, можно оставить как helper
    // БЕЗ @Override:

    public int getPadCount(byte[] block) {
        if (block == null) {
            throw new IllegalArgumentException("block must not be null");
        }

        if (block.length == 0) {
            throw new IllegalArgumentException("block length must be > 0");
        }

        int padCount = block[block.length - 1] & 0xFF;

        if (padCount < 1 || padCount > block.length) {
            throw new IllegalArgumentException("Invalid ANSI X9.23 padding value: " + padCount);
        }

        int start = block.length - padCount;

        for (int i = start; i < block.length - 1; i++) {
            if (block[i] != 0) {
                throw new IllegalArgumentException("Invalid ANSI X9.23 padding bytes");
            }
        }

        return padCount;
    }
}
