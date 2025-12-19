package com.pavel.crypto.core;

import java.util.Arrays;

public class CipherConfig {

    public enum Algorithm {
        DES,
        TRIPLE_DES,
        DEAL,
        RIJNDAEL,
        IDEA,
        RC4
    }

    public enum Mode {
        ECB,
        CBC,
        PCBC,
        CFB,
        OFB,
        CTR,
        RANDOM_DELTA,
        STREAM
    }

    public enum PaddingType {
        NONE,
        ZEROS,
        ANSI_X923,
        PKCS7,
        ISO_10126
    }

    private Algorithm algorithm;
    private Mode mode;
    private PaddingType padding;
    private byte[] key;
    private byte[] iv;
    private int threads;

    public CipherConfig(Algorithm algorithm,
                        Mode mode,
                        PaddingType padding,
                        byte[] key,
                        byte[] iv,
                        int threads) {

        this.algorithm = algorithm;
        this.mode = mode;
        this.padding = padding;

        if (key != null) {
            this.key = key.clone();
        } else {
            this.key = null;
        }

        if (iv != null) {
            this.iv = iv.clone();
        } else {
            this.iv = null;
        }

        if (threads <= 0) {
            this.threads = 1;
        } else {
            this.threads = threads;
        }
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public Mode getMode() {
        return mode;
    }

    public PaddingType getPadding() {
        return padding;
    }

    public byte[] getKey() {
        if (key == null) {
            return null;
        }

        return key.clone();
    }

    public byte[] getIv() {
        if (iv == null) {
            return null;
        }

        return iv.clone();
    }

    public int getThreads() {
        return threads;
    }

    @Override
    public String toString() {
        String keyInfo;
        String ivInfo;

        if (key != null) {
            keyInfo = key.length + " bytes";
        } else {
            keyInfo = "null";
        }

        if (iv != null) {
            ivInfo = Arrays.toString(iv);
        } else {
            ivInfo = "null";
        }

        return "CipherConfig{" +
                "algorithm=" + algorithm +
                ", mode=" + mode +
                ", padding=" + padding +
                ", key=" + keyInfo +
                ", iv=" + ivInfo +
                ", threads=" + threads +
                '}';
    }
}
