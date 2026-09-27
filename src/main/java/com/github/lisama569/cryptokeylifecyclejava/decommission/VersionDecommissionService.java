package com.github.lisama569.cryptokeylifecyclejava.decommission;

import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionActiveException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionDecommissionedException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionStillReferencedException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 受保护的密钥版本安全下线。
 *
 * <p>完整闭环：
 * <ol>
 *   <li>{@link #preflight(int)} 只判定、不改状态，返回与引用统计一致的结论；</li>
 *   <li>{@link #decommission(int)} 在共享 {@link MaintenanceLock} 内“再判定一次引用 →
 *       状态机切换 RETIRED→DECOMMISSIONED”，与数据迁移互斥，杜绝半停用；</li>
 * </ol>
 *
 * <p>并发语义：针对同一版本的并发下线被维护锁串行化，最终<b>恰好一个成功</b>，
 * 其余请求看到 {@code DECOMMISSIONED} 并得到一致的 {@code VERSION_DECOMMISSIONED}
 * 冲突结果；针对服务中版本（{@code VERSION_ACTIVE}）、仍被引用版本
 * （{@code VERSION_STILL_REFERENCED}）、不存在版本（{@code UNKNOWN_VERSION}）
 * 的拒绝原因彼此可区分。
 */
public class VersionDecommissionService {

    private static final Logger log = LoggerFactory.getLogger(VersionDecommissionService.class);

    private final KeyManager keyManager;
    private final DataRepository repository;
    private final MaintenanceLock maintenanceLock;
    private final VersionReferenceService referenceService;

    public VersionDecommissionService(KeyManager keyManager, DataRepository repository,
                                      MaintenanceLock maintenanceLock,
                                      VersionReferenceService referenceService) {
        this.keyManager = keyManager;
        this.repository = repository;
        this.maintenanceLock = maintenanceLock;
        this.referenceService = referenceService;
    }

    /** 安全下线预检：实时引用统计 + 可下线结论，不改变任何状态。 */
    public VersionReferenceReport preflight(int version) {
        return referenceService.inspect(version);
    }

    /**
     * 执行安全下线。
     *
     * @throws VersionActiveException           版本正在提供服务（ACTIVE）
     * @throws VersionStillReferencedException  仍有历史数据引用该版本
     * @throws VersionDecommissionedException   版本已下线（含并发抢跑后重复提交）
     * @throws RevokedVersionException          版本已被吊销
     * @throws com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException 版本不存在
     */
    public KeyVersion decommission(int version) {
        maintenanceLock.lock();
        try {
            // 锁内重入 inspect（ReentrantLock 可重入）：判定与统计走同一条一致快照路径
            VersionReferenceReport report = referenceService.inspect(version);
            if (!report.canDecommission()) {
                reject(report);
            }
            // 引用清零 + RETIRED 已在锁内确认；状态机在生命周期锁内原子切换
            try {
                KeyVersion result = keyManager.decommission(version);
                log.info("op=DECOMMISSION result=ACCEPT basis=GATE_PASSED version={} referencesAtGate=0 state={}",
                        version, result.state());
                return result;
            } catch (RevokedVersionException | VersionDecommissionedException
                     | VersionActiveException | KeyConflictException stateChanged) {
                // 极端并发：预检与状态切换之间版本被吊销等；原样抛出可区分原因，不留半状态
                log.warn("op=DECOMMISSION result=REJECT basis=STATE_CHANGED version={} reason={}",
                        version, stateChanged.reasonCode());
                throw stateChanged;
            }
        } finally {
            maintenanceLock.unlock();
        }
    }

    private void reject(VersionReferenceReport report) {
        String reason = report.blockedReason();
        int version = report.version();
        switch (reason) {
            case VersionReferenceService.REASON_CURRENTLY_ACTIVE -> {
                log.warn("op=DECOMMISSION result=REJECT basis=CURRENTLY_ACTIVE version={}", version);
                throw new VersionActiveException(
                        "key version " + version + " is the active serving version and cannot be decommissioned");
            }
            case VersionReferenceService.REASON_STILL_REFERENCED -> {
                log.warn("op=DECOMMISSION result=REJECT basis=STILL_REFERENCED version={} references={}",
                        version, report.references());
                throw new VersionStillReferencedException(
                        "key version " + version + " still has " + report.references()
                                + " data references; run targeted cleanup before decommissioning");
            }
            case VersionReferenceService.REASON_ALREADY_DECOMMISSIONED -> {
                log.warn("op=DECOMMISSION result=REJECT basis=ALREADY_DECOMMISSIONED version={}", version);
                throw new VersionDecommissionedException(
                        "key version " + version + " is already decommissioned");
            }
            case VersionReferenceService.REASON_ALREADY_REVOKED -> {
                log.warn("op=DECOMMISSION result=REJECT basis=ALREADY_REVOKED version={}", version);
                throw new RevokedVersionException(
                        "key version " + version + " is revoked and cannot be decommissioned");
            }
            case VersionReferenceService.REASON_NOT_RETIRED -> {
                log.warn("op=DECOMMISSION result=REJECT basis=NOT_RETIRED version={}", version);
                throw new KeyConflictException(
                        "key version " + version + " is not retired and cannot be decommissioned");
            }
            default -> throw new KeyConflictException(
                    "key version " + version + " cannot be decommissioned: " + reason);
        }
    }
}
