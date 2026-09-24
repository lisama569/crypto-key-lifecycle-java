package com.github.lisama569.cryptokeylifecyclejava.lifecycle;

import com.github.lisama569.cryptokeylifecyclejava.audit.AuditLogger;
import com.github.lisama569.cryptokeylifecyclejava.config.KeyLifecycleProperties;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidKeyVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedKeyVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownKeyVersionException;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecordStore;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import javax.crypto.KeyGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

/**
 * 密钥生命周期管理器。
 *
 * <p>并发模型：一把 {@link ReentrantReadWriteLock} 保护版本表与“当前版本”指针。
 * <ul>
 *   <li>读锁：加解密路径在整个“取版本→加解密”期间持有，保证与轮换的线性一致；</li>
 *   <li>写锁：启用/轮换/吊销期间持有，轮换与任何加解密互不穿插；</li>
 *   <li>rotationGuard：并发触发轮换时，只有一个能进入，其余快速失败（CONCURRENT_ROTATION）。</li>
 * </ul>
 */
@Component
public class KeyLifecycleManager {

    private final AuditLogger auditLogger;
    private final EncryptedRecordStore recordStore;
    private final KeyLifecycleProperties properties;

    private final ReentrantReadWriteLock rwLock = new ReentrantReadWriteLock(true);
    private final NavigableMap<Integer, KeyVersion> versions = new TreeMap<>();
    private final AtomicInteger versionSequence = new AtomicInteger(0);
    private final AtomicBoolean rotationGuard = new AtomicBoolean(false);
    private volatile Integer currentVersionId;

    /**
     * 测试钩子：在已持有 rotationGuard 与写锁、完成版本切换之后、释放锁之前执行。
     * 生产环境为 null；测试注入短延迟即可让并发轮换确定性交叠。
     */
    private volatile Runnable rotationCommitHook;

    /** 注入测试钩子（生产代码不得调用）；传 null 清除。 */
    public void setRotationCommitHook(Runnable hook) {
        this.rotationCommitHook = hook;
    }

    public KeyLifecycleManager(AuditLogger auditLogger,
                               EncryptedRecordStore recordStore,
                               KeyLifecycleProperties properties) {
        this.auditLogger = auditLogger;
        this.recordStore = recordStore;
        this.properties = properties;
    }

    @PostConstruct
    void bootstrap() {
        if (properties.isBootstrapKeyOnStartup()) {
            rwLock.writeLock().lock();
            try {
                if (versions.isEmpty()) {
                    KeyVersion first = createKeyLocked();
                    first.setState(KeyState.ENABLED);
                    currentVersionId = first.getVersion();
                    auditLogger.log("ENABLE", first.getVersion(), "ALLOWED",
                            "bootstrap initial version on startup");
                }
            } finally {
                rwLock.writeLock().unlock();
            }
        }
    }

    /** 在整个读锁临界区内执行（加解密路径使用，保证看到一致的版本视图）。 */
    public <T> T withReadLock(Supplier<T> action) {
        rwLock.readLock().lock();
        try {
            return action.get();
        } finally {
            rwLock.readLock().unlock();
        }
    }

    /** 生成一个 CREATED 状态的新版本。 */
    public KeyVersion generateKey() {
        rwLock.writeLock().lock();
        try {
            KeyVersion key = createKeyLocked();
            auditLogger.log("GENERATE", key.getVersion(), "ALLOWED", "new version created");
            return key;
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /**
     * 启用指定版本：该版本成为当前版本，原当前版本转为 RETIRED。
     * 只有 CREATED 版本可启用；重复启用 ENABLED 版本、复用 RETIRED/REVOKED 版本均被拒绝。
     */
    public KeyVersion enableVersion(int version) {
        rwLock.writeLock().lock();
        try {
            KeyVersion target = versions.get(version);
            if (target == null) {
                auditLogger.log("ENABLE", version, "REJECTED", "unknown version");
                throw new UnknownKeyVersionException("key version " + version + " does not exist");
            }
            switch (target.getState()) {
                case ENABLED -> {
                    auditLogger.log("ENABLE", version, "REJECTED", "already enabled, duplicate enable denied");
                    throw new InvalidKeyVersionException(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.INVALID_VERSION_STATE,
                            "key version " + version + " is already enabled; duplicate enable is not allowed");
                }
                case RETIRED -> {
                    auditLogger.log("ENABLE", version, "REJECTED", "retired version cannot be re-enabled");
                    throw new InvalidKeyVersionException(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.INVALID_VERSION_STATE,
                            "retired key version " + version + " cannot be re-enabled");
                }
                case REVOKED -> {
                    auditLogger.log("ENABLE", version, "REJECTED", "revoked version cannot be enabled");
                    throw new RevokedKeyVersionException("key version " + version + " is revoked");
                }
                default -> { /* CREATED: proceed */ }
            }
            Integer previousId = currentVersionId;
            if (previousId != null) {
                KeyVersion previous = versions.get(previousId);
                if (previous != null && previous.getState() == KeyState.ENABLED) {
                    previous.setState(KeyState.RETIRED);
                    auditLogger.log("RETIRE", previous.getVersion(), "ALLOWED",
                            "superseded by version " + version);
                }
            }
            target.setState(KeyState.ENABLED);
            currentVersionId = version;
            auditLogger.log("ENABLE", version, "ALLOWED",
                    previousId == null ? "first enabled version" : "replaced version " + previousId);
            return target;
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /**
     * 原子轮换：生成新版本并启用，旧版本进入 RETIRED。
     * 并发触发时只有一个成功，其余抛 CONCURRENT_ROTATION；
     * guard 与写锁双重保护，失败路径恢复 guard，不会留下半更新状态。
     */
    public KeyVersion rotate() {
        if (!rotationGuard.compareAndSet(false, true)) {
            auditLogger.log("ROTATE", null, "REJECTED",
                    "another rotation is in progress, concurrent trigger denied");
            throw new InvalidKeyVersionException(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.CONCURRENT_ROTATION,
                    "a rotation is already in progress");
        }
        try {
            rwLock.writeLock().lock();
            try {
                KeyVersion fresh = createKeyLocked();
                int newVersion = fresh.getVersion();
                Integer previousId = currentVersionId;
                // 状态转换在同一把写锁内连续完成：外部永远观察不到“无当前版本”的中间态
                fresh.setState(KeyState.ENABLED);
                if (previousId != null) {
                    KeyVersion previous = versions.get(previousId);
                    if (previous != null && previous.getState() == KeyState.ENABLED) {
                        previous.setState(KeyState.RETIRED);
                    }
                }
                currentVersionId = newVersion;
                if (rotationCommitHook != null) {
                    rotationCommitHook.run();
                }
                auditLogger.log("ROTATE", newVersion, "ALLOWED",
                        previousId == null ? "initial rotation" : "previous version " + previousId + " retired");
                return fresh;
            } finally {
                rwLock.writeLock().unlock();
            }
        } finally {
            rotationGuard.set(false);
        }
    }

    /**
     * 吊销版本（终态）。
     * <ul>
     *   <li>未知版本：UNKNOWN_VERSION；已吊销：REVOKED_VERSION；</li>
     *   <li>当前 ENABLED 版本不允许直接吊销（先轮换）；</li>
     *   <li>RETIRED 版本仍被数据引用时：REFERENCES_REMAIN（需先完成历史迁移）。</li>
     * </ul>
     */
    public void revokeVersion(int version) {
        rwLock.writeLock().lock();
        try {
            KeyVersion target = versions.get(version);
            if (target == null) {
                auditLogger.log("REVOKE", version, "REJECTED", "unknown version");
                throw new UnknownKeyVersionException("key version " + version + " does not exist");
            }
            switch (target.getState()) {
                case REVOKED -> {
                    auditLogger.log("REVOKE", version, "REJECTED", "already revoked");
                    throw new RevokedKeyVersionException("key version " + version + " is already revoked");
                }
                case ENABLED -> {
                    auditLogger.log("REVOKE", version, "REJECTED",
                            "cannot revoke the current enabled version; rotate first");
                    throw new InvalidKeyVersionException(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.INVALID_VERSION_STATE,
                            "cannot revoke current enabled version " + version + "; rotate to a new version first");
                }
                case CREATED -> {
                    auditLogger.log("REVOKE", version, "REJECTED", "version never enabled");
                    throw new InvalidKeyVersionException(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.INVALID_VERSION_STATE,
                            "key version " + version + " was never enabled and cannot be revoked");
                }
                case RETIRED -> {
                    long remaining = recordStore.countByVersion(version);
                    if (remaining > 0) {
                        auditLogger.log("REVOKE", version, "REJECTED",
                                "references remain: " + remaining + " record(s)");
                        throw new com.github.lisama569.cryptokeylifecyclejava.error.ReferencesRemainException(
                                "key version " + version + " still referenced by " + remaining + " record(s); "
                                        + "migrate historical data before revoking");
                    }
                    target.setState(KeyState.REVOKED);
                    auditLogger.log("REVOKE", version, "ALLOWED", "no references remain, version revoked");
                }
            }
        } finally {
            rwLock.writeLock().unlock();
        }
    }

    /** 返回当前启用版本。 */
    public KeyVersion currentVersion() {
        rwLock.readLock().lock();
        try {
            if (currentVersionId == null) {
                throw new InvalidKeyVersionException(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.INVALID_VERSION_STATE,
                        "no enabled key version exists");
            }
            return versions.get(currentVersionId);
        } finally {
            rwLock.readLock().unlock();
        }
    }

    /** 按版本号获取版本；未知版本以 UNKNOWN_VERSION 拒绝。不做状态限制。 */
    public KeyVersion requireVersion(int version) {
        rwLock.readLock().lock();
        try {
            KeyVersion key = versions.get(version);
            if (key == null) {
                throw new UnknownKeyVersionException("key version " + version + " does not exist");
            }
            return key;
        } finally {
            rwLock.readLock().unlock();
        }
    }

    /**
     * 解密路径专用：REVOKED 版本一律拒绝（REVOKED_VERSION）；
     * CREATED 版本尚未投入使用，同样拒绝（INVALID_VERSION_STATE）。
     */
    public KeyVersion requireVersionForDecrypt(int version) {
        rwLock.readLock().lock();
        try {
            KeyVersion key = versions.get(version);
            if (key == null) {
                auditLogger.log("DECRYPT", version, "REJECTED", "unknown version");
                throw new UnknownKeyVersionException("key version " + version + " does not exist");
            }
            switch (key.getState()) {
                case REVOKED -> {
                    auditLogger.log("DECRYPT", version, "REJECTED", "revoked version");
                    throw new RevokedKeyVersionException("key version " + version + " is revoked");
                }
                case CREATED -> {
                    auditLogger.log("DECRYPT", version, "REJECTED", "version not in service");
                    throw new InvalidKeyVersionException(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.INVALID_VERSION_STATE,
                            "key version " + version + " is not in service");
                }
                default -> {
                    return key;
                }
            }
        } finally {
            rwLock.readLock().unlock();
        }
    }

    /** 列出全部版本（按版本号升序）。 */
    public List<KeyVersionInfo> listVersions() {
        rwLock.readLock().lock();
        try {
            List<KeyVersionInfo> infos = new ArrayList<>(versions.size());
            for (KeyVersion key : versions.values()) {
                infos.add(new KeyVersionInfo(key.getVersion(), key.getState(), key.getCreatedAt(),
                        Integer.valueOf(key.getVersion()).equals(currentVersionId)));
            }
            return infos;
        } finally {
            rwLock.readLock().unlock();
        }
    }

    /** 调用方必须已持有写锁。 */
    private KeyVersion createKeyLocked() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(properties.getKeySizeBits());
            int id = versionSequence.incrementAndGet();
            KeyVersion key = new KeyVersion(id, keyGenerator.generateKey(), Instant.now(), KeyState.CREATED);
            versions.put(id, key);
            return key;
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate AES key", e);
        }
    }
}
