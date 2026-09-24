package com.github.lisama569.cryptokeylifecyclejava.crypto;

/**
 * 一段密文的自描述载体：记录所用密钥版本、IV 与含 GCM 认证标签的密文。
 * 线路/存储编码为 {@code v1:<keyVersion> base64url(iv) . base64url(ciphertextAndTag)}。
 * 篡改任意一段都会在解密时触发 {@code IntegrityFailure}。
 */
public final class CipherPayload {

    private final int keyVersion;
    private final byte[] iv;
    private final byte[] ciphertextWithTag;

    public CipherPayload(int keyVersion, byte[] iv, byte[] ciphertextWithTag) {
        this.keyVersion = keyVersion;
        this.iv = iv;
        this.ciphertextWithTag = ciphertextWithTag;
    }

    public int getKeyVersion() {
        return keyVersion;
    }

    public byte[] getIv() {
        return iv;
    }

    public byte[] getCiphertextWithTag() {
        return ciphertextWithTag;
    }
}
