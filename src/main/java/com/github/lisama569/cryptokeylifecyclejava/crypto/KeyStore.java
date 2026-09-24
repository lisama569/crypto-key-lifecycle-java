package com.github.lisama569.cryptokeylifecyclejava.crypto;

import java.util.List;
import java.util.Optional;
import javax.crypto.SecretKey;

/** 密钥版本存储抽象：内存或本地文件持久化实现。 */
public interface KeyStore {
    int nextVersion();
    void put(KeyVersion meta, SecretKey key);
    Optional<KeyVersion> find(int version);
    Optional<SecretKey> findKey(int version);
    Optional<KeyVersion> current();
    List<KeyVersion> all();
    void updateState(KeyVersion meta);

    /**
     * 删除一个从未进入可用状态（PENDING）的种子版本，用于轮换失败回滚。
     * 若版本不存在或已不处于 PENDING，则不做任何改动。
     */
    void removeIfPending(int version);
}
