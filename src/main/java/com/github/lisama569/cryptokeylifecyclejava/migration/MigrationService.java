package com.github.lisama569.cryptokeylifecyclejava.migration;

import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import java.util.List;
import java.util.concurrent.locks.ReentrantLock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 历史数据迁移服务：把旧版本密文重加密到当前 ACTIVE 版本。
 *
 * <p>语义保证：
 * <ul>
 *   <li><b>幂等</b>：候选记录仅以“密文版本 != 当前版本”判定。已经在目标版本的记录跳过；
 *       重复迁移不会改变明文含义（解旧密文 → 用新版本重新加密），也不会产生冲突状态；</li>
 *   <li><b>可中断续跑</b>：每条记录独立提交（CAS 状态切换），处理到 {@code limit}
 *       即返回进度；再次调用从剩余旧版本记录继续，无需从头开始；</li>
 *   <li><b>进度可核验</b>：{@link MigrationProgress} 含总数/已迁移/跳过/失败，
 *       {@code completed} 由实时扫描得出；</li>
 *   <li><b>并发安全</b>：迁移批次在服务级锁内串行；与在线加密/解密不互斥；</li>
 *   <li><b>失败安全</b>：源版本被吊销等失败只计入 failed 并保留原密文，
 *       不破坏数据，错误信息不含明文。</li>
 * </ul>
 */
public class MigrationService {

    private static final Logger log = LoggerFactory.getLogger(MigrationService.class);

    private final KeyManager keyManager;
    private final DataRepository repository;
    private final ReentrantLock migrationLock = new ReentrantLock();

    public MigrationService(KeyManager keyManager, DataRepository repository) {
        this.keyManager = keyManager;
        this.repository = repository;
    }

    /**
     * 执行一批迁移到当前 ACTIVE 版本。
     *
     * @param limit 本批最多迁移多少条旧版本记录；null 或 &lt;=0 表示一次性处理全部
     */
    public MigrationProgress migrateToCurrent(Integer limit) {
        KeyVersion target = keyManager.currentVersion();
        int targetVersion = target.version();

        migrationLock.lock();
        try {
            List<DataRecord> snapshot = repository.findAll();
            int total = snapshot.size();
            int migrated = 0;
            int skipped = 0;
            int failed = 0;
            int oldestFrom = targetVersion;

            for (DataRecord record : snapshot) {
                if (record.keyVersion() == targetVersion) {
                    // 已是目标版本：幂等跳过，重复迁移不改动密文与状态
                    skipped++;
                    continue;
                }
                if (limit != null && limit > 0 && (migrated + failed) >= limit) {
                    break; // 批量边界：中断点，剩余旧版本记录下次续跑
                }
                oldestFrom = Math.min(oldestFrom, record.keyVersion());
                try {
                    migrateOne(record, targetVersion);
                    migrated++;
                    log.info("op=MIGRATE result=ACCEPT basis=RE_ENCRYPTED id={} fromVersion={} toVersion={}",
                            record.id(), record.keyVersion(), targetVersion);
                } catch (AlreadyMigratedException e) {
                    // 并发下已被其它流程迁移：按幂等跳过处理，不算失败、不产生冲突状态
                    skipped++;
                    log.info("op=MIGRATE result=SKIP basis=ALREADY_MIGRATED id={}", record.id());
                } catch (KeyLifecycleException e) {
                    failed++;
                    log.warn("op=MIGRATE result=FAIL basis={} id={} fromVersion={} toVersion={}",
                            e.reasonCode(), record.id(), record.keyVersion(), targetVersion);
                }
            }

            MigrationProgress progress = buildProgress(oldestFrom, targetVersion, total,
                    migrated, skipped, failed);
            log.info("op=MIGRATE_BATCH result=DONE basis=PROGRESS fromVersion={} toVersion={} total={} migrated={} skipped={} failed={} completed={}",
                    oldestFrom, targetVersion, total, migrated, skipped, failed, progress.completed());
            return progress;
        } finally {
            migrationLock.unlock();
        }
    }

    /**
     * 按来源版本定向清理：只把 {@code fromVersion} 这一代旧数据重加密到当前 ACTIVE 版本，
     * 不触碰其他代旧版本的数据。
     *
     * <p>与 {@link #migrateToCurrent(Integer)} 同样保证幂等（已在目标版本的记录跳过）、
     * 可中断续跑（每批处理 {@code limit} 条，剩余下次继续）、失败隔离（单条失败保留原密文）。
     * 多代旧版本并存时各代可独立清理：清理完某一代后其引用数精确归零，其他代不受影响。
     *
     * @param fromVersion 要清理的来源版本；必须已知且不是当前 ACTIVE 版本
     * @param limit       本批最多处理多少条；null 或 &lt;=0 表示一次性处理全部
     */
    public SourceCleanupProgress migrateFromVersion(int fromVersion, Integer limit) {
        KeyVersion target = keyManager.currentVersion();
        int targetVersion = target.version();
        if (fromVersion == targetVersion) {
            log.warn("op=CLEANUP result=REJECT basis=SOURCE_IS_ACTIVE fromVersion={}", fromVersion);
            throw new KeyConflictException(
                    "cannot clean up the currently active version " + fromVersion);
        }
        boolean known = keyManager.listVersions().stream()
                .anyMatch(v -> v.version() == fromVersion);
        if (!known) {
            log.warn("op=CLEANUP result=REJECT basis=UNKNOWN_VERSION fromVersion={}", fromVersion);
            throw new UnknownVersionException("unknown key version: " + fromVersion);
        }

        migrationLock.lock();
        try {
            List<DataRecord> snapshot = repository.findAll();
            int sourceTotal = 0;
            for (DataRecord record : snapshot) {
                if (record.keyVersion() == fromVersion) {
                    sourceTotal++;
                }
            }
            int migrated = 0;
            int skipped = 0;
            int failed = 0;

            for (DataRecord record : snapshot) {
                if (record.keyVersion() != fromVersion) {
                    continue; // 定向清理：其他代旧版本与目标版本记录一律不触碰
                }
                if (limit != null && limit > 0 && (migrated + failed) >= limit) {
                    break; // 批量边界：中断点，剩余同代记录下次续跑
                }
                try {
                    migrateOne(record, targetVersion);
                    migrated++;
                    log.info("op=CLEANUP result=ACCEPT basis=RE_ENCRYPTED id={} fromVersion={} toVersion={}",
                            record.id(), fromVersion, targetVersion);
                } catch (AlreadyMigratedException e) {
                    skipped++;
                    log.info("op=CLEANUP result=SKIP basis=ALREADY_MIGRATED id={}", record.id());
                } catch (KeyLifecycleException e) {
                    failed++;
                    log.warn("op=CLEANUP result=FAIL basis={} id={} fromVersion={} toVersion={}",
                            e.reasonCode(), record.id(), fromVersion, targetVersion);
                }
            }

            int remaining = countOnVersion(fromVersion);
            SourceCleanupProgress progress = new SourceCleanupProgress(fromVersion, targetVersion,
                    sourceTotal, migrated, skipped, failed, remaining, remaining == 0);
            log.info("op=CLEANUP_BATCH result=DONE basis=PROGRESS fromVersion={} toVersion={} sourceTotal={} migrated={} skipped={} failed={} remaining={} completed={}",
                    fromVersion, targetVersion, sourceTotal, migrated, skipped, failed,
                    remaining, progress.completed());
            return progress;
        } finally {
            migrationLock.unlock();
        }
    }

    /** 实时统计仍停留在指定版本的记录条数（定向清理收敛核验与下线门禁共用口径）。 */
    private int countOnVersion(int version) {
        int count = 0;
        for (DataRecord record : repository.findAll()) {
            if (record.keyVersion() == version) {
                count++;
            }
        }
        return count;
    }

    private void migrateOne(DataRecord record, int targetVersion) {
        // 1) 用旧版本解密（RETIRED 保留期内允许；REVOKED/未知版本被拒绝，由上层计入失败）
        String plaintext = keyManager.decrypt(record.ciphertext());
        // 2) 用当前 ACTIVE 版本重新加密
        String reEncrypted = keyManager.encrypt(plaintext);
        // 3) CAS 提交：仅当记录未被并发改动时写入，避免互相覆盖
        boolean swapped = repository.compareAndUpdateStatus(
                record.id(), record.status(), RecordStatus.CURRENT, reEncrypted, targetVersion);
        if (!swapped) {
            throw new AlreadyMigratedException(record.id());
        }
    }

    private MigrationProgress buildProgress(int fromVersion, int targetVersion, int total,
                                            int migrated, int skipped, int failed) {
        int remaining = (int) repository.findAll().stream()
                .filter(r -> r.keyVersion() != targetVersion)
                .count();
        return new MigrationProgress(fromVersion, targetVersion, total, migrated, skipped, failed,
                remaining, remaining == 0);
    }

    /** 实时进度快照，不依赖上一次批量调用的局部计数。 */
    public MigrationProgress progress() {
        int targetVersion = keyManager.currentVersion().version();
        List<DataRecord> all = repository.findAll();
        long done = all.stream().filter(r -> r.keyVersion() == targetVersion).count();
        long remaining = all.size() - done;
        int oldest = all.stream().mapToInt(DataRecord::keyVersion).min().orElse(targetVersion);
        return new MigrationProgress(oldest, targetVersion, all.size(),
                (int) done, 0, 0, (int) remaining, remaining == 0);
    }

    /** 记录已被并发迁移的内部信号，按“跳过”处理。 */
    private static final class AlreadyMigratedException extends KeyLifecycleException {
        AlreadyMigratedException(String id) { super("record already migrated concurrently: " + id); }
        @Override public String reasonCode() { return "ALREADY_MIGRATED"; }
    }
}
