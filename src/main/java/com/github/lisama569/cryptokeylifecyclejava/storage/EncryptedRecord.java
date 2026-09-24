package com.github.lisama569.cryptokeylifecyclejava.storage;

/**
 * 一条加密数据记录。cipherText 为 AeadCipherService 的线路编码字符串。
 * 版本号冗余存于记录上，用于引用计数与迁移扫描；写入后通过 CAS 乐观更新。
 */
public final class EncryptedRecord {

    private final String id;
    private volatile int keyVersion;
    private volatile String cipherText;
    private volatile long updatedAt;

    public EncryptedRecord(String id, int keyVersion, String cipherText, long updatedAt) {
        this.id = id;
        this.keyVersion = keyVersion;
        this.cipherText = cipherText;
        this.updatedAt = updatedAt;
    }

    public String getId() {
        return id;
    }

    public int getKeyVersion() {
        return keyVersion;
    }

    public void setKeyVersion(int keyVersion) {
        this.keyVersion = keyVersion;
    }

    public String getCipherText() {
        return cipherText;
    }

    public void setCipherText(String cipherText) {
        this.cipherText = cipherText;
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }
}
