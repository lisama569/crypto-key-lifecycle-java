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
     * 删除一个未完成轮换切换的新版本，用于轮换失败回滚。
     * 仅当该版本处于 PENDING，或处于 ACTIVE 但尚未完成整次轮换（调用方保证旧版本会/已恢复
     * ACTIVE）时删除；RETIRED/REVOKED/DECOMMISSIONED 等已定型版本绝不删除。
     * 若版本不存在则不做任何改动。
     */
    void removeUnfinishedVersion(int version);
}
