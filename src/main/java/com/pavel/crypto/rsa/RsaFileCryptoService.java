package com.pavel.crypto.rsa;

import com.pavel.crypto.math.NumberTheoryService; // поправь пакет под свой
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class RsaFileCryptoService implements AutoCloseable {

    private final NumberTheoryService numberTheoryService;
    private final ExecutorService executor;

    public RsaFileCryptoService(NumberTheoryService numberTheoryService, int threadCount) {
        if (numberTheoryService == null) {
            throw new IllegalArgumentException("numberTheoryService must not be null");
        }

        if (threadCount <= 0) {
            throw new IllegalArgumentException("threadCount must be >= 1");
        }

        this.numberTheoryService = numberTheoryService;
        this.executor = Executors.newFixedThreadPool(threadCount);
    }

    // Синхронное шифрование / расшифрование файлов
    public void encryptFile(Path input,
                            Path output,
                            BigInteger n,
                            BigInteger e) throws IOException {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }

        if (output == null) {
            throw new IllegalArgumentException("output must not be null");
        }

        if (n == null || e == null) {
            throw new IllegalArgumentException("n/e must not be null");
        }

        byte[] fileData = Files.readAllBytes(input);

        byte[] encrypted = encryptBytes(fileData, n, e);

        Files.write(output, encrypted);
    }

    public void decryptFile(Path input,
                            Path output,
                            BigInteger n,
                            BigInteger d) throws IOException {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }

        if (output == null) {
            throw new IllegalArgumentException("output must not be null");
        }

        if (n == null || d == null) {
            throw new IllegalArgumentException("n/d must not be null");
        }

        byte[] cipherData = Files.readAllBytes(input);

        byte[] decrypted = decryptBytes(cipherData, n, d);

        Files.write(output, decrypted);
    }

    // Синхронное шифрование / расшифрование байтов
    public byte[] encryptBytes(byte[] data,
                               BigInteger n,
                               BigInteger e) {
        if (data == null) {
            throw new IllegalArgumentException("data must not be null");
        }

        if (n == null || e == null) {
            throw new IllegalArgumentException("n/e must not be null");
        }

        if (n.signum() <= 0) {
            throw new IllegalArgumentException("n must be positive");
        }

        int nBitLength = n.bitLength();
        int keyBytes = (nBitLength + 7) / 8;
        int maxPlainBlockLen = (nBitLength - 1) / 8;

        if (maxPlainBlockLen <= 0) {
            throw new IllegalArgumentException("n is too small");
        }

        // Вставляем длину исходных данных (8 байт, big-endian)
        long dataLength = data.length;
        if (dataLength < 0) {
            throw new IllegalArgumentException("data length must be non-negative");
        }

        byte[] withLen = new byte[8 + data.length];
        writeLongBigEndian(withLen, 0, dataLength);
        System.arraycopy(data, 0, withLen, 8, data.length);

        int totalPlain = withLen.length;
        int fullBlocks = totalPlain / maxPlainBlockLen;
        int tail = totalPlain % maxPlainBlockLen;

        int blockCount;
        if (tail == 0) {
            blockCount = fullBlocks;
        } else {
            blockCount = fullBlocks + 1;
        }

        int cipherBlockSize = keyBytes;
        byte[] result = new byte[blockCount * cipherBlockSize];

        int plainPos = 0;
        int outPos = 0;

        int i = 0;
        while (i < blockCount) {
            int bytesLeft = totalPlain - plainPos;
            int currentBlockLen = maxPlainBlockLen;

            if (bytesLeft < maxPlainBlockLen) {
                currentBlockLen = bytesLeft;
            }

            byte[] block = new byte[maxPlainBlockLen];

            if (currentBlockLen > 0) {
                System.arraycopy(withLen, plainPos, block, 0, currentBlockLen);
            }

            plainPos = plainPos + currentBlockLen;

            BigInteger m = new BigInteger(1, block);
            BigInteger c = numberTheoryService.modPow(m, e, n);

            byte[] cipherBlock = toFixedLengthBytes(c, cipherBlockSize);

            System.arraycopy(cipherBlock, 0, result, outPos, cipherBlockSize);
            outPos = outPos + cipherBlockSize;

            i = i + 1;
        }

        return result;
    }

    public byte[] decryptBytes(byte[] cipherData,
                               BigInteger n,
                               BigInteger d) {
        if (cipherData == null) {
            throw new IllegalArgumentException("cipherData must not be null");
        }

        if (n == null || d == null) {
            throw new IllegalArgumentException("n/d must not be null");
        }

        if (n.signum() <= 0) {
            throw new IllegalArgumentException("n must be positive");
        }

        if (cipherData.length == 0) {
            return new byte[0];
        }

        int nBitLength = n.bitLength();
        int keyBytes = (nBitLength + 7) / 8;
        int maxPlainBlockLen = (nBitLength - 1) / 8;

        if (cipherData.length % keyBytes != 0) {
            throw new IllegalArgumentException("cipherData length must be multiple of keyBytes");
        }

        int blockCount = cipherData.length / keyBytes;
        byte[] plainWithLen = new byte[blockCount * maxPlainBlockLen];

        int inPos = 0;
        int outPos = 0;
        int i = 0;

        while (i < blockCount) {
            byte[] cipherBlock = new byte[keyBytes];
            System.arraycopy(cipherData, inPos, cipherBlock, 0, keyBytes);
            inPos = inPos + keyBytes;

            BigInteger c = new BigInteger(1, cipherBlock);
            BigInteger m = numberTheoryService.modPow(c, d, n);

            byte[] plainBlock = toFixedLengthBytes(m, maxPlainBlockLen);

            System.arraycopy(plainBlock, 0, plainWithLen, outPos, maxPlainBlockLen);
            outPos = outPos + maxPlainBlockLen;

            i = i + 1;
        }

        if (plainWithLen.length < 8) {
            throw new IllegalStateException("Decrypted data length < 8 bytes");
        }

        long dataLength = readLongBigEndian(plainWithLen, 0);

        if (dataLength < 0) {
            throw new IllegalStateException("Negative data length after decryption");
        }

        long available = plainWithLen.length - 8L;
        if (dataLength > available) {
            throw new IllegalStateException(
                    "Decrypted length (" + dataLength + ") > available bytes (" + available + ")"
            );
        }

        int resultLen = (int) dataLength;

        byte[] result = new byte[resultLen];
        if (resultLen > 0) {
            System.arraycopy(plainWithLen, 8, result, 0, resultLen);
        }

        return result;
    }

    // Async-обёртки для файлов

    public Future<Void> encryptFileAsync(final Path input,
                                         final Path output,
                                         final BigInteger n,
                                         final BigInteger e) {
        Callable<Void> task = new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                encryptFile(input, output, n, e);
                return null;
            }
        };

        return executor.submit(task);
    }

    public Future<Void> decryptFileAsync(final Path input,
                                         final Path output,
                                         final BigInteger n,
                                         final BigInteger d) {
        Callable<Void> task = new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                decryptFile(input, output, n, d);
                return null;
            }
        };

        return executor.submit(task);
    }

    // Вспомогательные методы

    private void writeLongBigEndian(byte[] arr, int offset, long value) {
        arr[offset]     = (byte) (value >>> 56);
        arr[offset + 1] = (byte) (value >>> 48);
        arr[offset + 2] = (byte) (value >>> 40);
        arr[offset + 3] = (byte) (value >>> 32);
        arr[offset + 4] = (byte) (value >>> 24);
        arr[offset + 5] = (byte) (value >>> 16);
        arr[offset + 6] = (byte) (value >>> 8);
        arr[offset + 7] = (byte) (value);
    }

    private long readLongBigEndian(byte[] arr, int offset) {
        long b0 = arr[offset]     & 0xFFL;
        long b1 = arr[offset + 1] & 0xFFL;
        long b2 = arr[offset + 2] & 0xFFL;
        long b3 = arr[offset + 3] & 0xFFL;
        long b4 = arr[offset + 4] & 0xFFL;
        long b5 = arr[offset + 5] & 0xFFL;
        long b6 = arr[offset + 6] & 0xFFL;
        long b7 = arr[offset + 7] & 0xFFL;

        long value = 0L;
        value = value | (b0 << 56);
        value = value | (b1 << 48);
        value = value | (b2 << 40);
        value = value | (b3 << 32);
        value = value | (b4 << 24);
        value = value | (b5 << 16);
        value = value | (b6 << 8);
        value = value | b7;

        return value;
    }

    private byte[] toFixedLengthBytes(BigInteger value, int length) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("value must be non-negative");
        }

        byte[] tmp = value.toByteArray();

        // Убираем возможный лишний ведущий байт знака
        if (tmp.length > 1 && tmp[0] == 0) {
            byte[] noSign = new byte[tmp.length - 1];
            System.arraycopy(tmp, 1, noSign, 0, noSign.length);
            tmp = noSign;
        }

        if (tmp.length > length) {
            throw new IllegalArgumentException(
                    "value does not fit in " + length + " bytes (got " + tmp.length + ")"
            );
        }

        if (tmp.length == length) {
            return tmp;
        }

        byte[] result = new byte[length];
        int offset = length - tmp.length;
        System.arraycopy(tmp, 0, result, offset, tmp.length);

        return result;
    }

    @Override
    public void close() {
        executor.shutdown();
    }
}
