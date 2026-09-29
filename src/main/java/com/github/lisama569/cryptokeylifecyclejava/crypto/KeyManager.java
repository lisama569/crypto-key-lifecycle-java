package com.github.lisama569.cryptokeylifecyclejava.crypto;

import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.RotationFailedException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.SecretKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 密钥生命周期门面。
 *
 * <p>状态机：
 * <pre>
 *   生成 → ACTIVE（首个版本）
 *   ACTIVE  --rotate()-->  RETIRED（旧） + ACTIVE（新）
 *   ACTIVE / RETIRED --revoke(v)--> REVOKED（终态）
 * </pre>
 *
 * <p>并发与原子性语义：
 * <ul>
 *   <li>{@code lifecycleLock} 保证“生成新密钥 + 旧版本转 RETIRED + 新版本 ACTIVE”整体
 *       串行，并发轮换互斥；轮换流程中任何异常都会在锁内回滚本次变更，不留半更新状态；</li>
 *   <li>轮换与在线加解密<b>不互斥</b>：加密不取生命周期锁。状态切换由
 *       {@link KeyStore#activateAndRetire} 在存储内部一次原子提交，加密侧只能观察到
 *       “切换前（旧版本 ACTIVE）”或“切换后（新版本 ACTIVE）”，任何时刻系统里都恰好
 *       有一个 ACTIVE，不存在“没有可用密钥版本”的窗口，写入不会因轮换而失败；</li>
 *   <li>加密始终读取当下唯一的 ACTIVE 版本，轮换后新数据只使用新版本；</li>
 *   <li>解密允许 ACTIVE 与保留期内的 RETIRED 版本，REVOKED 一律拒绝；</li>
 *   <li>同一版本不会被重复启用（put 拒绝重复版本号，状态机不允许逆向转换）。</li>
 * </ul>
 */
public class KeyManager {

    /** 一次轮换的结果：被退休的旧版本（首次生成时为 -1）与新启用版本。 */
    public record RotationResult(int previousVersion, KeyVersion active) { }

    private static final Logger log = LoggerFactory.getLogger(KeyManager.class);

    private final KeyStore keyStore;
    private final AesGcmCipher cipher;
    private final CipherCodec codec;
    private final int keyBits;
    private final ReentrantLock lifecycleLock = new ReentrantLock();

    public KeyManager(KeyStore keyStore, AesGcmCipher cipher, CipherCodec codec) {
        this(keyStore, cipher, codec, 256);
    }

    public KeyManager(KeyStore keyStore, AesGcmCipher cipher, CipherCodec codec, int keyBits) {
        this.keyStore = keyStore;
        this.cipher = cipher;
        this.codec = codec;
        this.keyBits = keyBits;
    }

    /** 生成首个密钥版本并直接启用；若已有 ACTIVE 版本则拒绝（避免重复启用）。 */
    public KeyVersion generateAndActivate() {
        lifecycleLock.lock();
        try {
            Optional<KeyVersion> existing = keyStore.current();
            if (existing.isPresent()) {
                log.warn("op=INITIATE result=REJECT reason=ALREADY_ACTIVE version={}",
                        existing.get().version());
                throw new KeyConflictException(
                        "an active key version already exists: " + existing.get().version());
            }
            int version = keyStore.nextVersion();
            SecretKey key = AesGcmCipher.generateKey(keyBits);
            KeyVersion meta = new KeyVersion(version, KeyState.ACTIVE, Instant.now(), null, null);
            keyStore.put(meta, key);
            log.info("op=GENERATE result=ACCEPT basis=FIRST_VERSION version={} state={}",
                    version, meta.state());
            return meta;
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * 原子轮换：当前 ACTIVE 版本转 RETIRED，同时新版本置为 ACTIVE。
     *
     * <p>无 ACTIVE 版本时先初始化首个版本（直接以 ACTIVE 落库，从不对外暴露
     * “没有 ACTIVE”的状态）。正常轮换分两步：先写入 PENDING 种子版本（不可用），
     * 再通过 {@link KeyStore#activateAndRetire} 在存储的<b>同一次原子更新</b>内完成
     * “新版本 ACTIVE + 旧版本 RETIRED”。并发加密不持有生命周期锁，但存储原子切换
     * 保证它读到的状态要么是切换前（旧 ACTIVE），要么是切换后（新 ACTIVE），
     * 轮换期间任何时刻都恰好有一个可用于加密的版本，写入不会因轮换而失败。
     *
     * <p>提交阶段抛错时在锁内回滚：旧版本恢复 ACTIVE、未启用的新版本移除，
     * 版本号可复用；并以 {@link RotationFailedException}（{@code ROTATION_FAILED}）
     * 给出与普通状态冲突可区分的失败原因。
     */
    public RotationResult rotate() {
        lifecycleLock.lock();
        try {
            KeyVersion current = keyStore.current().orElse(null);
            int newVersionNumber = keyStore.nextVersion();
            SecretKey newKey = AesGcmCipher.generateKey(keyBits);
            if (current == null) {
                // 首个版本：直接 ACTIVE，不存在旧版本，无中间窗口
                KeyVersion active = new KeyVersion(newVersionNumber, KeyState.ACTIVE,
                        Instant.now(), null, null);
                try {
                    keyStore.put(active, newKey);
                } catch (RuntimeException ex) {
                    throw rotationFailure(newVersionNumber, ex);
                }
                log.info("op=ROTATE result=ACCEPT basis=FIRST_VERSION_ACTIVE previousVersion=-1 activeVersion={}",
                        newVersionNumber);
                return new RotationResult(-1, active);
            }

            // 1) 密钥材料就绪：先以 PENDING 落库（不可用于加解密）
            KeyVersion pending = new KeyVersion(newVersionNumber, KeyState.PENDING,
                    Instant.now(), null, null);
            try {
                keyStore.put(pending, newKey);
            } catch (RuntimeException ex) {
                // 种子尚未写入，状态无任何变化
                throw rotationFailure(newVersionNumber, ex);
            }
            try {
                // 2) 原子切换：新→ACTIVE 与 旧→RETIRED 同时对外可见
                KeyVersion active = new KeyVersion(newVersionNumber, KeyState.ACTIVE,
                        pending.createdAt(), null, null);
                keyStore.activateAndRetire(active, current.version());

                log.info("op=ROTATE result=ACCEPT basis=ATOMIC_SWITCH previousVersion={} activeVersion={}",
                        current.version(), newVersionNumber);
                return new RotationResult(current.version(), active);
            } catch (RuntimeException ex) {
                rollbackAfterFailedRotate(current, pending);
                throw rotationFailure(newVersionNumber, ex);
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    private RotationFailedException rotationFailure(int intendedVersion, RuntimeException cause) {
        if (cause instanceof RotationFailedException rfe) {
            return rfe;
        }
        log.error("op=ROTATE result=FAIL basis=ROLLED_BACK intendedVersion={} error={}",
                intendedVersion, cause.getClass().getSimpleName());
        if (cause instanceof com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException kle) {
            return new RotationFailedException(
                    "key rotation failed and was rolled back: " + kle.getMessage(), cause);
        }
        return new RotationFailedException(
                "key rotation failed due to a storage error and was rolled back", cause);
    }

    private void rollbackAfterFailedRotate(KeyVersion previousActive, KeyVersion pendingNew) {
        try {
            // 旧版本若已被转 RETIRED，恢复为 ACTIVE
            if (previousActive != null && keyStore.find(previousActive.version())
                    .map(m -> m.state() == KeyState.RETIRED).orElse(false)) {
                keyStore.updateState(previousActive);
            }
            // 新种子版本从未启用，直接移除，版本链不留废版本；下一次轮换复用该版本号
            if (pendingNew != null) {
                keyStore.removeIfPending(pendingNew.version());
            }
        } catch (RuntimeException rollbackError) {
            log.error("op=ROTATE result=ROLLBACK_ERROR version={} error={}",
                    pendingNew == null ? -1 : pendingNew.version(),
                    rollbackError.getClass().getSimpleName());
        }
    }

    /** 吊销指定版本（ACTIVE 或 RETIRED 可吊销；未知/已吊销分别给出可区分原因）。 */
    public KeyVersion revoke(int version) {
        lifecycleLock.lock();
        try {
            KeyVersion current = requireVersion(version, "REVOKE");
            return switch (current.state()) {
                case REVOKED -> {
                    log.warn("op=REVOKE result=REJECT basis=ALREADY_REVOKED version={}", version);
                    throw new RevokedVersionException("key version " + version + " is already revoked");
                }
                case ACTIVE, RETIRED -> {
                    KeyVersion revoked = new KeyVersion(version, KeyState.REVOKED,
                            current.createdAt(), current.retiredAt(), Instant.now());
                    keyStore.updateState(revoked);
                    log.info("op=REVOKE result=ACCEPT basis=STATE_TRANSITION version={} {}->{}",
                            version, current.state(), KeyState.REVOKED);
                    yield revoked;
                }
                case PENDING -> {
                    log.warn("op=REVOKE result=REJECT basis=NOT_ACTIVATABLE version={} state={}",
                            version, current.state());
                    throw new KeyConflictException(
                            "key version " + version + " is pending and cannot be revoked");
                }
            };
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * 受保护的安全下线（decommission）：把不再被依赖的旧版本推进到终态 REVOKED。
     *
     * <p>与 {@link #revoke(int)} 的区别：revoke 是无条件吊销（运维强制手段），
     * decommission 是带门禁的安全下线，只有同时满足才允许成功：
     * <ul>
     *   <li>版本存在且处于 RETIRED（PENDING 为轮换中间态，ACTIVE 正在提供服务）；</li>
     *   <li>{@code referenceCount} 实时统计的引用条数为 0。</li>
     * </ul>
     *
     * <p>检查与状态转换在 {@code lifecycleLock} 内原子完成：并发抢同一版本时只有一个
     * 成功，其余看到 REVOKED 终态并收到 {@link RevokedVersionException}；
     * 重复提交同样得到 ALREADY_REVOKED 语义，不会出现半停用状态。
     *
     * @param version         要下线的版本号
     * @param referenceCount  实时引用统计（在锁内求值，保证判定与转换之间无并发漂移）
     */
    public KeyVersion decommission(int version, java.util.function.IntSupplier referenceCount) {
        lifecycleLock.lock();
        try {
            KeyVersion current = requireVersion(version, "DECOMMISSION");
            switch (current.state()) {
                case REVOKED -> {
                    log.warn("op=DECOMMISSION result=REJECT basis=ALREADY_REVOKED version={}", version);
                    throw new RevokedVersionException(
                            "key version " + version + " is already decommissioned (revoked)");
                }
                case ACTIVE -> {
                    log.warn("op=DECOMMISSION result=REJECT basis=STILL_SERVING version={} state={}",
                            version, current.state());
                    throw new com.github.lisama569.cryptokeylifecyclejava.error.ActiveVersionException(
                            "key version " + version + " is the active serving version");
                }
                case PENDING -> {
                    log.warn("op=DECOMMISSION result=REJECT basis=NOT_ACTIVATABLE version={} state={}",
                            version, current.state());
                    throw new KeyConflictException(
                            "key version " + version + " is pending and cannot be decommissioned");
                }
                case RETIRED -> {
                    int refs = referenceCount.getAsInt();
                    if (refs > 0) {
                        log.warn("op=DECOMMISSION result=REJECT basis=STILL_REFERENCED version={} references={}",
                                version, refs);
                        throw new com.github.lisama569.cryptokeylifecyclejava.error.VersionInUseException(
                                "key version " + version + " is still referenced by "
                                        + refs + " data record(s)");
                    }
                    KeyVersion revoked = new KeyVersion(version, KeyState.REVOKED,
                            current.createdAt(), current.retiredAt(), Instant.now());
                    keyStore.updateState(revoked);
                    log.info("op=DECOMMISSION result=ACCEPT basis=REFERENCES_ZERO version={} {}->{}",
                            version, current.state(), KeyState.REVOKED);
                    return revoked;
                }
                default -> throw new IllegalStateException("unhandled state: " + current.state());
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /** 使用当前 ACTIVE 版本加密。null/空明文被拒绝，绝不返回错误明文。 */
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            log.warn("op=ENCRYPT result=REJECT basis=EMPTY_INPUT");
            throw new InvalidInputException("plaintext must not be null or empty");
        }
        KeyVersion active = keyStore.current().orElseThrow(() -> {
            log.error("op=ENCRYPT result=REJECT basis=NO_ACTIVE_VERSION");
            return new KeyConflictException("no active key version available");
        });
        SecretKey key = keyStore.findKey(active.version())
                .orElseThrow(() -> new IllegalStateException("active key material missing"));
        byte[] data = plaintext.getBytes(StandardCharsets.UTF_8);
        CiphertextEnvelope envelope = cipher.encrypt(key, active.version(), data);
        log.debug("op=ENCRYPT result=ACCEPT basis=ACTIVE_VERSION version={}", active.version());
        return codec.encode(envelope);
    }

    /**
     * 按信封中的版本号解密：
     * 未知版本 → {@link UnknownVersionException}；
     * 已吊销版本 → {@link RevokedVersionException}；
     * 篡改/标签失败 → {@link IntegrityVerificationException}（由底层原语抛出）。
     */
    public String decrypt(String encodedCiphertext) {
        CiphertextEnvelope envelope = codec.decode(encodedCiphertext);
        int version = envelope.keyVersion();
        KeyVersion meta = requireVersion(version, "DECRYPT");
        if (meta.state() == KeyState.REVOKED) {
            log.warn("op=DECRYPT result=REJECT basis=REVOKED_VERSION version={}", version);
            throw new RevokedVersionException(
                    "key version " + version + " has been revoked; decryption refused");
        }
        if (meta.state() != KeyState.ACTIVE && meta.state() != KeyState.RETIRED) {
            log.warn("op=DECRYPT result=REJECT basis=STATE_NOT_USABLE version={} state={}",
                    version, meta.state());
            throw new KeyConflictException(
                    "key version " + version + " is not usable for decryption: " + meta.state());
        }
        SecretKey key = keyStore.findKey(version)
                .orElseThrow(() -> new IllegalStateException("key material missing for version " + version));
        byte[] plainBytes = cipher.decrypt(key, envelope);
        String plaintext = new String(plainBytes, StandardCharsets.UTF_8);
        log.debug("op=DECRYPT result=ACCEPT basis={} version={}", meta.state(), version);
        return plaintext;
    }

    public KeyVersion currentVersion() {
        return keyStore.current().orElseThrow(() ->
                new KeyConflictException("no active key version available"));
    }

    public List<KeyVersion> listVersions() {
        return keyStore.all();
    }

    private KeyVersion requireVersion(int version, String op) {
        return keyStore.find(version).orElseThrow(() -> {
            log.warn("op={} result=REJECT basis=UNKNOWN_VERSION version={}", op, version);
            return new UnknownVersionException("unknown key version: " + version);
        });
    }
}
