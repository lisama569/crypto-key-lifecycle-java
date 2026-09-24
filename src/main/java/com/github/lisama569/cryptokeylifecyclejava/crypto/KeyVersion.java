package com.github.lisama569.cryptokeylifecyclejava.crypto;

import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyState;

import javax.crypto.SecretKey;
import java.time.Instant;

/**
 * 一个受版本标识管理的密钥版本。密钥材料只在进程内存中持有，不参与
 * toString/序列化，避免意外泄露。
 */
public final class KeyVersion {

    private final int version;
    private final SecretKey secretKey;
    private final Instant createdAt;
    private volatile KeyState state;

    public KeyVersion(int version, SecretKey secretKey, Instant createdAt, KeyState state) {
        this.version = version;
        this.secretKey = secretKey;
        this.createdAt = createdAt;
        this.state = state;
    }

    public int getVersion() {
        return version;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public KeyState getState() {
        return state;
    }

    public void setState(KeyState state) {
        this.state = state;
    }

    @Override
    public String toString() {
        // 绝不输出密钥材料
        return "KeyVersion{version=" + version + ", state=" + state + ", createdAt=" + createdAt + "}";
    }
}
