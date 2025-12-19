package com.pavel.crypto.util;

public final class BitPermutation {

    // Чтобы получить i-й выходной бит, возьми permutation[i]-й входной

    private BitPermutation() {
    }

    public static long permute64(long value, int[] permutation) {
        long result = 0L;

        int length = permutation.length;

        for (int i = 0; i < length; i++) {
            int srcPosFromLeft = permutation[i];

            int srcPosFromRight = 64 - srcPosFromLeft;
            long bit = (value >> srcPosFromRight) & 1L;

            int destPosFromRight = length - 1 - i;

            result |= (bit << destPosFromRight);
        }

        return result;
    }

    public static byte[] permuteBytes(byte[] input, int[] permutation) {
        int bitCount = permutation.length;
        int byteCount = bitCount / 8;

        if (bitCount % 8 != 0) {
            byteCount = byteCount + 1;
        }

        byte[] output = new byte[byteCount];

        for (int i = 0; i < bitCount; i++) {
            int srcPosFromLeft = permutation[i];

            int srcIndex = (srcPosFromLeft - 1) / 8;
            int srcBitInByte = 7 - ((srcPosFromLeft - 1) % 8);

            int bit = (input[srcIndex] >> srcBitInByte) & 1;

            int destIndex = i / 8;
            int destBitInByte = 7 - (i % 8);

            output[destIndex] |= (byte) (bit << destBitInByte);
        }

        return output;
    }
}
