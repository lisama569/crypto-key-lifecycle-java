package com.github.lisama569.cryptokeylifecyclejava.lifecycle;

import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRepository;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 版本引用统计与安全下线（decommission）编排服务。
 *
 * <p>语义保证：
 * <ul>
 *   <li><b>统计一致性</b>：每次统计基于同一份数据快照（单次 {@code findAll}）与同一时刻
 *       的版本状态计算，{@code referenceCount} 与 {@code reason} 不会自相矛盾；
 *       迁移每提交一条记录，下一次统计即反映最新引用数；</li>
 *   <li><b>预检结论可区分</b>：{@code reason} 区分 SAFE_TO_DECOMMISSION（可下线）、
 *       BLOCKED_BY_REFERENCES（被数据引用挡住）、BLOCKED_ACTIVE_VERSION（当前在用版本）、
 *       ALREADY_DECOMMISSIONED（已是终态）；</li>
 *   <li><b>下线门禁原子性</b>：引用计数在 {@link KeyManager} 生命周期锁内实时求值，
 *       判定与状态转换之间不会插入并发迁移或并发下线；并发抢同一版本时只有一个成功，
 *       其余得到一致的 REVOKED_VERSION 冲突结果；</li>
 *   <li><b>无半停用</b>：下线要么完整进入 REVOKED 终态，要么整体拒绝并保持原状态，
 *       加解密判定不受影响。</li>
 * </ul>
 */
public class VersionLifecycleService {

    /** 预检结论：可以安全下线。 */
    public static final String REASON_SAFE = "SAFE_TO_DECOMMISSION";
    /** 预检结论：仍被数据记录引用。 */
    public static final String REASON_BLOCKED_BY_REFERENCES = "BLOCKED_BY_REFERENCES";
    /** 预检结论：是当前正在提供服务的 ACTIVE 版本。 */
    public static final String REASON_BLOCKED_ACTIVE = "BLOCKED_ACTIVE_VERSION";
    /** 预检结论：已处于 REVOKED 终态。 */
    public static final String REASON_ALREADY_DECOMMISSIONED = "ALREADY_DECOMMISSIONED";

    private static final Logger log = LoggerFactory.getLogger(VersionLifecycleService.class);

    private final KeyManager keyManager;
    private final DataRepository repository;

    public VersionLifecycleService(KeyManager keyManager, DataRepository repository) {
        this.keyManager = keyManager;
        this.repository = repository;
    }

    /**
     * 单个版本的引用统计与下线预检结论。
     * 未知版本抛出 {@link UnknownVersionException}（与解密/吊销的未知版本语义一致）。
     */
    public VersionReferenceStats statsFor(int version) {
        KeyVersion meta = keyManager.listVersions().stream()
                .filter(v -> v.version() == version)
                .findFirst()
                .orElseThrow(() -> {
                    log.warn("op=REFERENCES result=REJECT basis=UNKNOWN_VERSION version={}", version);
                    return new UnknownVersionException("unknown key version: " + version);
                });
        Map<Integer, Long> counts = countReferences();
        VersionReferenceStats stats = toStats(meta, counts.getOrDefault(version, 0L));
        log.info("op=REFERENCES result=OK basis={} version={} references={} state={}",
                stats.reason(), version, stats.referenceCount(), stats.state());
        return stats;
    }

    /** 全部版本的引用统计快照（按版本号升序），同一份数据快照保证互相一致。 */
    public List<VersionReferenceStats> stats() {
        Map<Integer, Long> counts = countReferences();
        List<VersionReferenceStats> all = keyManager.listVersions().stream()
                .map(v -> toStats(v, counts.getOrDefault(v.version(), 0L)))
                .toList();
        log.info("op=REFERENCES result=OK basis=SNAPSHOT versions={}", all.size());
        return all;
    }

    /**
     * 受保护的安全下线：仅当引用清零且该版本不是当前 ACTIVE 时进入 REVOKED 终态。
     *
     * <p>失败原因可区分：未知版本 → UNKNOWN_VERSION；当前 ACTIVE → VERSION_IS_ACTIVE；
     * 仍被引用 → VERSION_STILL_REFERENCED；已下线/重复提交/并发落败 → REVOKED_VERSION。
     */
    public KeyVersion decommission(int version) {
        // 引用计数作为 IntSupplier 传入，由 KeyManager 在生命周期锁内实时求值，
        // 保证“引用清零”的判定与状态转换原子生效，并发下线只有一个成功
        return keyManager.decommission(version, () -> countReferences(version));
    }

    /** 实时统计指定版本的引用条数（单次快照，供下线门禁在锁内调用）。 */
    private int countReferences(int version) {
        int count = 0;
        for (DataRecord record : repository.findAll()) {
            if (record.keyVersion() == version) {
                count++;
            }
        }
        return count;
    }

    /** 单次快照统计所有版本的引用条数，保证同一次查询内各自洽。 */
    private Map<Integer, Long> countReferences() {
        Map<Integer, Long> counts = new HashMap<>();
        for (DataRecord record : repository.findAll()) {
            counts.merge(record.keyVersion(), 1L, Long::sum);
        }
        return counts;
    }

    private VersionReferenceStats toStats(KeyVersion meta, long referenceCount) {
        boolean active = meta.state() == KeyState.ACTIVE;
        String reason;
        boolean safe;
        if (meta.state() == KeyState.REVOKED) {
            reason = REASON_ALREADY_DECOMMISSIONED;
            safe = false;
        } else if (active) {
            reason = REASON_BLOCKED_ACTIVE;
            safe = false;
        } else if (referenceCount > 0) {
            reason = REASON_BLOCKED_BY_REFERENCES;
            safe = false;
        } else {
            reason = REASON_SAFE;
            safe = true;
        }
        return new VersionReferenceStats(meta.version(), meta.state().name(),
                referenceCount, active, safe, reason);
    }
}
