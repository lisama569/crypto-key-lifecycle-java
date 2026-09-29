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

    /**
     * 原子提交一次轮换切换：把 {@code newActive} 置为 ACTIVE，同时把
     * {@code retiredVersion}（若存在）置为 RETIRED。两个状态变更必须在存储的
     * 同一次原子更新内对外可见——任何外部读者要么看到切换前的状态（旧版本 ACTIVE），
     * 要么看到切换后的状态（新版本 ACTIVE），绝不允许观察到“没有 ACTIVE”的中间态。
     *
     * <p>约束（违反则整体失败、不产生任何对外可见的变更）：新版本必须已以 PENDING 存在；
     * 被退休版本（若给定）当前必须为 ACTIVE。
     *
     * <p>默认实现仅用于未覆盖本方法的兼容场景，按两步原语顺序执行；生产存储
     * （{@code InMemoryKeyStore}）以同一把 monitor 临界区覆盖本方法，提供上述
     * 原子性保证。
     *
     * @param newActive      即将启用的版本元数据（状态必须为 ACTIVE）
     * @param retiredVersion 要退休的旧版本号；首个版本初始化时传 null
     */
    default void activateAndRetire(KeyVersion newActive, Integer retiredVersion) {
        // 顺序：先退休旧版本，再启用新版本。失败由 KeyManager 回滚。
        if (retiredVersion != null) {
            KeyVersion current = find(retiredVersion)
                    .orElseThrow(() -> new IllegalStateException(
                            "key version " + retiredVersion + " does not exist"));
            updateState(new KeyVersion(current.version(), KeyState.RETIRED,
                    current.createdAt(), java.time.Instant.now(), current.revokedAt()));
        }
        updateState(newActive);
    }
}
