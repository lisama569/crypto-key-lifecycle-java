package com.github.lisama569.cryptokeylifecyclejava.crypto;

import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.RotationRecoveryException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;
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
 *   <li>使用一把公平的读写锁 {@code lifecycleLock}：轮换/生成/吊销/下线等状态变更持<b>写锁</b>，
 *       在线加密持<b>读锁</b>。轮换内部“写入 PENDING → 旧版本转 RETIRED → 新版本转 ACTIVE”
 *       三步对外是<b>一个不可见的原子临界区</b>——外部任何时刻读到的版本视图都恰好有一个
 *       ACTIVE，不存在“没有可用版本”的空窗；因此在线加密与轮换可真正并发且永不因轮换失败。
 *       并发轮换被写锁串行化；同一版本不会被重复启用（put 拒绝重复版本号，状态机不允许逆向转换）。</li>
 *   <li>解密不需要锁：轮换中间态下旧版本是 RETIRED（保留期内允许解密）、新版本 PENDING
 *       不会出现在任何已产出的信封里，所以按信封版本读到的状态在解密语义上始终自洽，
 *       轮换不会阻塞历史数据解密。</li>
 *   <li>轮换流程中任何异常都在写锁内回滚本次变更（恢复旧版本 ACTIVE、移除未启用的 PENDING），
 *       不留半更新状态；干净回滚以 {@link KeyConflictException} 表达。若回滚本身失败或回滚后
 *       不满足“仍有（且仅有）一个 ACTIVE、无 PENDING 残留”的不变式，则抛出
 *       {@link RotationRecoveryException}（{@code ROTATION_RECOVERY_FAILED}），与普通冲突可区分。</li>
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
    // 公平锁：轮换在临界区内排队时，先到的在线加密优先拿到读锁完成，避免写线程长期插队饿死写入
    private final ReentrantReadWriteLock lifecycleLock = new ReentrantReadWriteLock(true);

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
        lifecycleLock.writeLock().lock();
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
            lifecycleLock.writeLock().unlock();
        }
    }

    /**
     * 原子轮换：当前 ACTIVE 版本转 RETIRED，同时新版本置为 ACTIVE。
     * 返回新版本元数据。无 ACTIVE 版本时先初始化（与 generateAndActivate 互斥，不会重复）。
     */
    public RotationResult rotate() {
        lifecycleLock.writeLock().lock();
        try {
            KeyVersion current = keyStore.current().orElse(null);
            int newVersionNumber = keyStore.nextVersion();
            KeyVersion newMeta = null;
            try {
                // 1) 先生成并写入新密钥（PENDING 不可用），保证密钥材料就绪后才切换状态
                SecretKey newKey = AesGcmCipher.generateKey(keyBits);
                newMeta = new KeyVersion(newVersionNumber, KeyState.PENDING, Instant.now(), null, null);
                keyStore.put(newMeta, newKey);

                // 2) 旧 ACTIVE -> RETIRED（保留期内仍可解密）
                if (current != null) {
                    KeyVersion retired = new KeyVersion(current.version(), KeyState.RETIRED,
                            current.createdAt(), Instant.now(), null);
                    keyStore.updateState(retired);
                }

                // 3) 新版本 PENDING -> ACTIVE
                KeyVersion active = new KeyVersion(newVersionNumber, KeyState.ACTIVE,
                        newMeta.createdAt(), null, null);
                keyStore.updateState(active);

                log.info("op=ROTATE result=ACCEPT basis=ATOMIC_SWITCH previousVersion={} activeVersion={}",
                        current == null ? -1 : current.version(), newVersionNumber);
                return new RotationResult(current == null ? -1 : current.version(), active);
            } catch (RuntimeException ex) {
                // 回滚：清除可能已写入的 PENDING 新版本；旧版本若已被转 RETIRED 则恢复 ACTIVE。
                // 回滚后必须回到轮换前的一致视图（有在用版本、无半更新），否则抛出可区分的恢复失败。
                rollbackAfterFailedRotate(current, newMeta, newVersionNumber);
                if (ex instanceof com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException) {
                    throw ex;
                }
                log.error("op=ROTATE result=FAIL basis=ROLLED_BACK intendedVersion={} error={}",
                        newVersionNumber, ex.getClass().getSimpleName());
                throw new KeyConflictException("key rotation failed and was rolled back");
            }
        } finally {
            lifecycleLock.writeLock().unlock();
        }
    }

    /**
     * 回滚一次失败的轮换并校验恢复后的不变式。
     *
     * @param previousActive 轮换开始前的在用版本（首次轮换为 null）
     * @param pendingNew     本次可能已写入的 PENDING 新版本（可能为 null）
     * @param intendedVersion 本次轮换打算启用的版本号（仅用于日志）
     * @throws RotationRecoveryException 回滚动作本身失败，或回滚后仍无在用版本 / 残留 PENDING
     */
    private void rollbackAfterFailedRotate(KeyVersion previousActive, KeyVersion pendingNew, int intendedVersion) {
        RuntimeException recoveryError = null;
        // 旧版本若已被转 RETIRED，恢复为 ACTIVE；新种子版本从未启用，直接移除，版本链不留废版本
        try {
            if (previousActive != null && keyStore.find(previousActive.version())
                    .map(m -> m.state() == KeyState.RETIRED).orElse(false)) {
                keyStore.updateState(previousActive);
            }
            if (pendingNew != null) {
                keyStore.removeIfPending(pendingNew.version());
            }
        } catch (RuntimeException rollbackError) {
            recoveryError = rollbackError;
            log.error("op=ROTATE result=ROLLBACK_ERROR version={} error={}",
                    intendedVersion, rollbackError.getClass().getSimpleName());
        }

        // 恢复后不变式：首次轮换失败应回到“空系统”；否则必须恰好有一个 ACTIVE 且无 PENDING 残留
        long activeCount = keyStore.all().stream().filter(m -> m.state() == KeyState.ACTIVE).count();
        long pendingCount = keyStore.all().stream().filter(m -> m.state() == KeyState.PENDING).count();
        boolean consistent = previousActive == null
                ? activeCount == 0 && pendingCount == 0
                : activeCount == 1 && pendingCount == 0
                    && keyStore.find(previousActive.version())
                            .map(m -> m.state() == KeyState.ACTIVE).orElse(false);
        if (!consistent || recoveryError != null) {
            String msg = "key rotation failed at version " + intendedVersion
                    + " and recovery left the key set in an unsafe state"
                    + " (active=" + activeCount + ", pending=" + pendingCount + ")";
            if (recoveryError != null) {
                throw new RotationRecoveryException(msg + ": " + recoveryError.getMessage(), recoveryError);
            }
            throw new RotationRecoveryException(msg);
        }
    }

    /** 吊销指定版本（ACTIVE 或 RETIRED 可吊销；未知/已吊销分别给出可区分原因）。 */
    public KeyVersion revoke(int version) {
        lifecycleLock.writeLock().lock();
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
            lifecycleLock.writeLock().unlock();
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
        lifecycleLock.writeLock().lock();
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
            lifecycleLock.writeLock().unlock();
        }
    }

    /**
     * 使用当前 ACTIVE 版本加密。null/空明文被拒绝，绝不返回错误明文。
     *
     * <p>持读锁：与轮换等状态变更互斥、与其他并发加密共享。因此调用方看到的版本视图要么是
     * 切换前的旧 ACTIVE、要么是切换后的新 ACTIVE，绝不会看到“没有可用版本”的轮换中间态，
     * 在线写入不会因为轮换而失败。
     */
    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isEmpty()) {
            log.warn("op=ENCRYPT result=REJECT basis=EMPTY_INPUT");
            throw new InvalidInputException("plaintext must not be null or empty");
        }
        lifecycleLock.readLock().lock();
        try {
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
        } finally {
            lifecycleLock.readLock().unlock();
        }
    }

    /**
     * 按信封中的版本号解密（不持生命周期锁）：
     * 未知版本 → {@link UnknownVersionException}；
     * 已吊销版本 → {@link RevokedVersionException}；
     * 篡改/标签失败 → {@link IntegrityVerificationException}（由底层原语抛出）。
     *
     * <p>轮换中间态对解密也是安全的：旧版本处于 RETIRED（保留期内允许解密），
     * PENDING 新版本尚未产生任何信封，因此不会被任何密文引用，轮换不会阻塞或破坏历史数据解密。
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
