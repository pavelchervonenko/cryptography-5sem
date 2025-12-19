package com.pavel.crypto.symmetric;

import com.pavel.crypto.core.BlockCipher;
import com.pavel.crypto.core.CipherMode;
import com.pavel.crypto.padding.NoPadding;
import com.pavel.crypto.core.Padding;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Supplier;

public class SymmetricCryptoService implements AutoCloseable {

    private final Supplier<BlockCipher> cipherSupplier;
    private final Supplier<CipherMode> modeSupplier;
    private final Padding padding;
    private final ExecutorService executor;

    public SymmetricCryptoService(Supplier<BlockCipher> cipherSupplier,
                                  Supplier<CipherMode> modeSupplier,
                                  Padding padding,
                                  int threadCount) {
        if (cipherSupplier == null) {
            throw new IllegalArgumentException("cipherSupplier must not be null");
        }

        if (modeSupplier == null) {
            throw new IllegalArgumentException("modeSupplier must not be null");
        }

        if (padding == null) {
            throw new IllegalArgumentException("padding must not be null");
        }

        if (threadCount <= 0) {
            throw new IllegalArgumentException("threadCount must be >= 1");
        }

        this.cipherSupplier = cipherSupplier;
        this.modeSupplier = modeSupplier;
        this.padding = padding;
        this.executor = Executors.newFixedThreadPool(threadCount);
    }

    // Работа с массивами байт (синхронно)

    public byte[] encryptBytes(byte[] plaintext, byte[] key, byte[] iv) {
        if (plaintext == null) {
            throw new IllegalArgumentException("plaintext must not be null");
        }

        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }

        BlockCipher cipher = cipherSupplier.get();
        cipher.init(true, key);

        CipherMode mode = modeSupplier.get();
        mode.init(true, cipher, iv);

        int blockSize = cipher.getBlockSize();

        if (blockSize <= 0) {
            throw new IllegalStateException("Block size must be > 0");
        }

        boolean isNoPadding = padding instanceof NoPadding;

        int fullBlocks = plaintext.length / blockSize;
        int tailLen = plaintext.length % blockSize;

        if (isNoPadding && tailLen != 0) {
            throw new IllegalArgumentException(
                    "Data length must be multiple of block size when using NoPadding"
            );
        }

        int totalBlocks;

        if (isNoPadding) {
            totalBlocks = fullBlocks;
        } else {
            totalBlocks = fullBlocks + 1;
        }

        byte[] output = new byte[totalBlocks * blockSize];

        int inPos = 0;
        int outPos = 0;

        // Все полные блоки для любых паддингов
        int i = 0;

        while (i < fullBlocks) {
            mode.processBlock(plaintext, inPos, output, outPos);
            inPos = inPos + blockSize;
            outPos = outPos + blockSize;
            i = i + 1;
        }

        if (isNoPadding) {
            return output;
        }

        // Последний блок с паддингом
        byte[] lastBlock = new byte[blockSize];
        int padOffset;

        if (tailLen > 0) {
            System.arraycopy(plaintext, inPos, lastBlock, 0, tailLen);
            padOffset = tailLen;
        } else {
            padOffset = 0;
        }

        padding.addPadding(lastBlock, padOffset);

        mode.processBlock(lastBlock, 0, output, outPos);

        return output;
    }

    public byte[] decryptBytes(byte[] ciphertext, byte[] key, byte[] iv) {
        if (ciphertext == null) {
            throw new IllegalArgumentException("ciphertext must not be null");
        }

        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }

        if (ciphertext.length == 0) {
            return new byte[0];
        }

        BlockCipher cipher = cipherSupplier.get();
        cipher.init(false, key);

        CipherMode mode = modeSupplier.get();
        mode.init(false, cipher, iv);

        int blockSize = cipher.getBlockSize();

        if (ciphertext.length % blockSize != 0) {
            throw new IllegalArgumentException("ciphertext length must be multiple of block size");
        }

        int blocks = ciphertext.length / blockSize;
        byte[] temp = new byte[ciphertext.length];

        int inPos = 0;
        int outPos = 0;
        int i = 0;

        while (i < blocks) {
            mode.processBlock(ciphertext, inPos, temp, outPos);
            inPos = inPos + blockSize;
            outPos = outPos + blockSize;
            i = i + 1;
        }

        boolean isNoPadding = padding instanceof NoPadding;

        if (isNoPadding) {
            // В режиме без паддинга возвращаем всё
            byte[] result = new byte[temp.length];
            System.arraycopy(temp, 0, result, 0, temp.length);
            return result;
        }

        int lastBlockOffset = temp.length - blockSize;

        int dataInLastBlock = padding.removePadding(temp, lastBlockOffset, blockSize);

        if (dataInLastBlock < 0 || dataInLastBlock > blockSize) {
            throw new IllegalStateException("Invalid dataInLastBlock value: " + dataInLastBlock);
        }

        int padCount = blockSize - dataInLastBlock;
        int dataLength = temp.length - padCount;

        byte[] result = new byte[dataLength];

        if (dataLength > 0) {
            System.arraycopy(temp, 0, result, 0, dataLength);
        }

        return result;
    }

    // Работа с массивами байт (асинхронно)

    public Future<byte[]> encryptBytesAsync(final byte[] plaintext,
                                            final byte[] key,
                                            final byte[] iv) {
        Callable<byte[]> task = new Callable<byte[]>() {
            @Override
            public byte[] call() {
                return encryptBytes(plaintext, key, iv);
            }
        };

        return executor.submit(task);
    }

    public Future<byte[]> decryptBytesAsync(final byte[] ciphertext,
                                            final byte[] key,
                                            final byte[] iv) {
        Callable<byte[]> task = new Callable<byte[]>() {
            @Override
            public byte[] call() {
                return decryptBytes(ciphertext, key, iv);
            }
        };

        return executor.submit(task);
    }

    // Работа с файлами (синхронно)

    public void encryptFile(Path input,
                            Path output,
                            byte[] key,
                            byte[] iv) throws IOException {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }

        if (output == null) {
            throw new IllegalArgumentException("output must not be null");
        }

        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }

        byte[] data = Files.readAllBytes(input);

        byte[] encrypted = encryptBytes(data, key, iv);

        Files.write(output, encrypted);
    }

    public void decryptFile(Path input,
                            Path output,
                            byte[] key,
                            byte[] iv) throws IOException {
        if (input == null) {
            throw new IllegalArgumentException("input must not be null");
        }

        if (output == null) {
            throw new IllegalArgumentException("output must not be null");
        }

        if (key == null) {
            throw new IllegalArgumentException("key must not be null");
        }

        byte[] data = Files.readAllBytes(input);

        byte[] decrypted = decryptBytes(data, key, iv);

        Files.write(output, decrypted);
    }

    // Работа с файлами (асинхронно / многопоточно)

    public Future<Void> encryptFileAsync(final Path input,
                                         final Path output,
                                         final byte[] key,
                                         final byte[] iv) {
        Callable<Void> task = new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                encryptFile(input, output, key, iv);
                return null;
            }
        };

        return executor.submit(task);
    }

    public Future<Void> decryptFileAsync(final Path input,
                                         final Path output,
                                         final byte[] key,
                                         final byte[] iv) {
        Callable<Void> task = new Callable<Void>() {
            @Override
            public Void call() throws Exception {
                decryptFile(input, output, key, iv);
                return null;
            }
        };

        return executor.submit(task);
    }

    // Управление пулом потоков

    @Override
    public void close() {
        executor.shutdown();
    }
}
