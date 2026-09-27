package com.github.lisama569.cryptokeylifecyclejava.decommission;

import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRepository;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 版本引用统计与安全下线预检。
 *
 * <p>一致性保证：统计在共享 {@link MaintenanceLock} 内完成“读版本状态 + 全量扫描引用计数”，
 * 与历史数据改写（全量/定向迁移）以及安全下线互斥。因此报告中的状态、引用数来自同一时刻，
 * 不会出现“引用清零但仍有旧数据指向该版本”这类自相矛盾的结论；迁移每批结束后（锁释放点）
 * 的下一次查询即可观察到引用数实时下降。
 */
public class VersionReferenceService {

    /** 阻塞原因码，与异常 reasonCode 对齐，便于预检与实际拒绝结果互相对照。 */
    public static final String REASON_CURRENTLY_ACTIVE = "CURRENTLY_ACTIVE";
    public static final String REASON_STILL_REFERENCED = "STILL_REFERENCED";
    public static final String REASON_ALREADY_DECOMMISSIONED = "ALREADY_DECOMMISSIONED";
    public static final String REASON_ALREADY_REVOKED = "ALREADY_REVOKED";
    public static final String REASON_NOT_RETIRED = "NOT_RETIRED";

    private static final Logger log = LoggerFactory.getLogger(VersionReferenceService.class);

    private final KeyManager keyManager;
    private final DataRepository repository;
    private final MaintenanceLock maintenanceLock;

    public VersionReferenceService(KeyManager keyManager, DataRepository repository,
                                   MaintenanceLock maintenanceLock) {
        this.keyManager = keyManager;
        this.repository = repository;
        this.maintenanceLock = maintenanceLock;
    }

    /**
     * 查看某版本的实时引用统计与下线预检结论。未知版本抛 UnknownVersionException（404）。
     */
    public VersionReferenceReport inspect(int version) {
        maintenanceLock.lock();
        try {
            // 未知版本由 KeyManager 抛 UNKNOWN_VERSION，与加解密路径保持一致
            KeyVersion meta = keyManager.getVersion(version);
            List<DataRecord> snapshot = repository.findAll();
            long references = snapshot.stream().filter(r -> r.keyVersion() == version).count();
            int activeVersion = currentActiveVersion();

            String blockedReason = blockedReason(meta.state(), version, references, activeVersion);
            boolean canDecommission = blockedReason == null;

            VersionReferenceReport report = new VersionReferenceReport(
                    version, meta.state().name(), references, activeVersion, canDecommission,
                    blockedReason,
                    meta.decommissionedAt() == null ? null : meta.decommissionedAt().toString());
            log.info("op=INSPECT_REFERENCES result=DONE basis={} version={} state={} references={} activeVersion={} canDecommission={}",
                    blockedReason == null ? "DECOMMISSIONABLE" : blockedReason,
                    version, meta.state(), references, activeVersion, canDecommission);
            return report;
        } finally {
            maintenanceLock.unlock();
        }
    }

    /**
     * 判定阻塞原因；返回 null 表示可安全下线。
     * 可下线的唯一组合：状态为 RETIRED、引用清零、且不是当前服务版本。
     */
    static String blockedReason(KeyState state, int version, long references, int activeVersion) {
        return switch (state) {
            case DECOMMISSIONED -> REASON_ALREADY_DECOMMISSIONED;
            case ACTIVE -> REASON_CURRENTLY_ACTIVE;
            case REVOKED -> REASON_ALREADY_REVOKED;
            case PENDING -> REASON_NOT_RETIRED;
            case RETIRED -> {
                if (version == activeVersion) {
                    // 理论上不会发生（ACTIVE 与 RETIRED 互斥），防御性处理
                    yield REASON_CURRENTLY_ACTIVE;
                }
                yield references > 0 ? REASON_STILL_REFERENCED : null;
            }
        };
    }

    private int currentActiveVersion() {
        try {
            return keyManager.currentVersion().version();
        } catch (KeyConflictException noActive) {
            return -1;
        }
    }
}
