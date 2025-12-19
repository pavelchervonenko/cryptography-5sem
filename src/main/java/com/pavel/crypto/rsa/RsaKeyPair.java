package com.pavel.crypto.rsa;

public class RsaKeyPair {

    private final RsaPublicKey publicKey;
    private final RsaPrivateKey privateKey;

    public RsaKeyPair(RsaPublicKey publicKey, RsaPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public RsaPublicKey getPublicKey() {
        return publicKey;
    }

    public RsaPrivateKey getPrivateKey() {
        return privateKey;
    }
}
