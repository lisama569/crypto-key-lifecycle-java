package com.github.lisama569.cryptokeylifecyclejava.migration;

import com.github.lisama569.cryptokeylifecyclejava.audit.AuditLogger;
import com.github.lisama569.cryptokeylifecyclejava.crypto.AeadCipherService;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherPayload;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.FailureReason;
import com.github.lisama569.cryptokeylifecyclejava.error.MigrationException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyLifecycleManager;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecord;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecordStore;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 历史数据迁移器。
 *
 * <p>语义保证：
 * <ul>
 *   <li><b>幂等</b>：每条记录处理前检查版本——不是源版本则跳过；已迁到目标版本的记录
 *       在重跑时直接跳过，明文含义不发生任何变化；</li>
 *   <li><b>可中断续跑</b>：按 id 字典序分批，每批结束落 checkpoint（最后已处理 id），
 *       中断后凭 migrationId 调用即可从 checkpoint 之后续跑；</li>
 *   <li><b>进度可核验</b>：进度中的 remainingByVersion 每次都来自全表实时计数，
 *       与 migrated/skipped 独立，可交叉验证；</li>
 *   <li><b>无半更新</b>：解密→新加密→CAS 替换，替换失败则原密文原样保留；</li>
 *   <li><b>无冲突状态</b>：CAS 检测并发改写，冲突记录计入 failed 并标记 FAILED，
 *       同一条数据不会同时呈现两种互相冲突的版本状态。</li>
 * </ul>
 */
@Component
public class HistoricalDataMigrator {

    private final KeyLifecycleManager keyLifecycleManager;
    private final AeadCipherService cipherService;
    private final EncryptedRecordStore recordStore;
    private final AuditLogger auditLogger;
    private final ConcurrentHashMap<String, MutableProgress> migrations = new ConcurrentHashMap<>();

    public HistoricalDataMigrator(KeyLifecycleManager keyLifecycleManager,
                                  AeadCipherService cipherService,
                                  EncryptedRecordStore recordStore,
                                  AuditLogger auditLogger) {
        this.keyLifecycleManager = keyLifecycleManager;
        this.cipherService = cipherService;
        this.recordStore = recordStore;
        this.auditLogger = auditLogger;
    }

    /**
     * 启动（或继续）一次迁移。
     *
     * @param fromVersion 源版本，必须处于 RETIRED（保留期内、可解密）
     * @param batchSize   每批处理记录数，处理完即落 checkpoint
     * @param maxBatches  本次调用最多处理多少批；-1 表示一直跑到完成
     * @param resumeId    续跑传入已有 migrationId；新建传 null
     */
    public MigrationProgress migrate(int fromVersion, int batchSize, int maxBatches, String resumeId) {
        if (batchSize <= 0) {
            throw new MigrationException(FailureReason.INVALID_INPUT, "batchSize must be positive");
        }
        MutableProgress progress = resolveOrCreate(fromVersion, resumeId);

        synchronized (progress) {
            if (progress.status == MigrationStatus.RUNNING) {
                throw new MigrationException(FailureReason.MIGRATION_NOT_RUNNABLE,
                        "migration " + progress.migrationId + " is already running");
            }
            progress.interrupted = false;
            progress.runMigrated = 0;
            progress.runSkipped = 0;
            progress.runFailed = 0;
            // COMPLETED 的迁移被再次调用 = 幂等核验：放开 checkpoint 全表重扫，
            // 仍引用源版本的记录（若有）会被迁，其余全部 SKIPPED。
            // FAILED/PAUSED 必须保留 checkpoint，从断点继续。
            if (progress.status == MigrationStatus.COMPLETED) {
                progress.checkpointId = null;
                progress.finishedAt = null;
            }
            progress.status = MigrationStatus.RUNNING;
        }

        // 每次进入都重新核验前置条件：源版本必须仍可解密，目标必须是当前 ENABLED 版本
        KeyVersion source = keyLifecycleManager.requireVersion(fromVersion);
        KeyVersion target;
        try {
            if (source.getState() != KeyState.RETIRED) {
                throw new MigrationException(FailureReason.MIGRATION_NOT_RUNNABLE,
                        "source version " + fromVersion + " must be RETIRED to migrate its data");
            }
            target = keyLifecycleManager.currentVersion();
            if (target.getState() != KeyState.ENABLED || target.getVersion() == fromVersion) {
                throw new MigrationException(FailureReason.MIGRATION_NOT_RUNNABLE,
                        "migration requires a different current enabled version");
            }
        } catch (MigrationException e) {
            synchronized (progress) {
                progress.status = MigrationStatus.FAILED;
            }
            auditLogger.log("MIGRATE", fromVersion, "REJECTED", e.getReason().name());
            throw e;
        }

        int targetVersion = target.getVersion();
        if (progress.toVersion != targetVersion) {
            // 目标版本固定为创建/首次续跑时的当前启用版本，避免一次迁移跨越两个目标
            throw new MigrationException(FailureReason.MIGRATION_NOT_RUNNABLE,
                    "migration target changed since start; expected " + progress.toVersion
                            + " but current enabled is " + targetVersion);
        }

        auditLogger.log("MIGRATE", fromVersion, "ALLOWED",
                "migration " + progress.migrationId + " -> version " + targetVersion
                        + ", batchSize=" + batchSize + ", resumeFrom=" + progress.checkpointId);

        List<EncryptedRecord> scan = recordStore.snapshot();
        long budget = maxBatches < 0 ? Long.MAX_VALUE : (long) maxBatches * batchSize;
        // budget 同时是“滞留重扫 + 主扫描”在本轮调用内处理记录总数的上限。
        // 主扫描每成功（含跳过）一条就把 checkpoint 推到该 id，因此主扫描只从 checkpoint 之后继续，
        // 不会重复处理，PAUSED 续跑的 migrated 增量精确等于本轮新处理的源版本记录数。
        int mainStart = 0;
        if (progress.checkpointId != null) {
            while (mainStart < scan.size()
                    && scan.get(mainStart).getId().compareTo(progress.checkpointId) <= 0) {
                mainStart++;
            }
        }

        long processedInCall = 0;
        boolean exhausted = true;

        // 阶段一：滞留重扫。仅重新检查 [0, mainStart) 中仍引用源版本的记录
        //（典型：上一轮 CAS 冲突未修复的记录）；已迁走的记录不花预算、直接忽略。
        for (int idx = 0; idx < mainStart; idx++) {
            EncryptedRecord record = scan.get(idx);
            if (record.getKeyVersion() != fromVersion) {
                continue;
            }
            if (progress.interrupted) {
                exhausted = false;
                auditLogger.log("MIGRATE", fromVersion, "PAUSED",
                        "interrupted during stranded rescan at " + record.getId());
                break;
            }
            if (processedInCall >= budget) {
                exhausted = false;
                break;
            }
            processOne(record, source, target, progress);
            processedInCall++;
        }

        // 阶段二：主扫描。checkpoint 之后的每条记录都处理（迁移或跳过），并推进 checkpoint。
        if (exhausted) {
            for (int idx = mainStart; idx < scan.size(); idx++) {
                EncryptedRecord record = scan.get(idx);
                if (progress.interrupted) {
                    exhausted = false;
                    auditLogger.log("MIGRATE", fromVersion, "PAUSED",
                            "interrupted after checkpoint " + progress.checkpointId);
                    break;
                }
                if (processedInCall >= budget) {
                    exhausted = false; // 批次额度用完，稍后可续跑
                    break;
                }
                processOne(record, source, target, progress);
                progress.checkpointId = record.getId();
                processedInCall++;
            }
        }

        return finalizeProgress(progress, fromVersion, exhausted, processedInCall);
    }

    /** 查询迁移进度（remainingByVersion 实时核验）。 */
    public MigrationProgress getProgress(String migrationId) {
        MutableProgress progress = migrations.get(migrationId);
        if (progress == null) {
            throw new MigrationException(FailureReason.UNKNOWN_VERSION,
                    "migration not found: " + migrationId);
        }
        synchronized (progress) {
            return progress.snapshot(recordStore.countByVersion(progress.fromVersion));
        }
    }

    /**
     * 请求中断某次正在跑的迁移：循环在处理下一条之前观测到标志并暂停，
     * 已处理记录的 checkpoint 保留，之后可凭 migrationId 续跑。
     */
    public void interrupt(String migrationId) {
        MutableProgress progress = migrations.get(migrationId);
        if (progress == null) {
            throw new MigrationException(FailureReason.UNKNOWN_VERSION,
                    "migration not found: " + migrationId);
        }
        progress.interrupted = true;
    }

    private MutableProgress resolveOrCreate(int fromVersion, String resumeId) {
        if (resumeId != null && !resumeId.isBlank()) {
            MutableProgress existing = migrations.get(resumeId);
            if (existing == null) {
                throw new MigrationException(FailureReason.UNKNOWN_VERSION,
                        "migration not found: " + resumeId);
            }
            if (existing.fromVersion != fromVersion) {
                throw new MigrationException(FailureReason.MIGRATION_NOT_RUNNABLE,
                        "migration " + resumeId + " belongs to source version " + existing.fromVersion
                                + ", not " + fromVersion);
            }
            return existing;
        }
        MutableProgress created = new MutableProgress(
                "mig-" + UUID.randomUUID(), fromVersion,
                keyLifecycleManager.currentVersion().getVersion(),
                recordStore.size());
        MutableProgress prior = migrations.putIfAbsent(created.migrationId, created);
        return prior == null ? created : prior;
    }

    private MigrationProgress finalizeProgress(MutableProgress progress, int fromVersion,
                                               boolean exhausted, long processedInCall) {
        long remaining = recordStore.countByVersion(fromVersion);
        synchronized (progress) {
            if (progress.runFailed > 0) {
                progress.status = MigrationStatus.FAILED;
            } else if (!exhausted || remaining > 0) {
                progress.status = MigrationStatus.PAUSED;
            } else {
                progress.status = MigrationStatus.COMPLETED;
                progress.finishedAt = Instant.now();
            }
            return progress.snapshot(remaining);
        }
    }

    /**
     * 测试钩子：每条记录在“读取快照之后、解密与 CAS 替换之前”被调用。
     * 生产环境为 null；测试可利用该窗口注入并发改写，确定性验证 CAS 防冲突。
     */
    private volatile java.util.function.BiConsumer<Integer, String> beforeRecordCasHook;

    /** 安装测试钩子（生产代码不得调用）；传 null 清除。 */
    public void setBeforeRecordCasHook(java.util.function.BiConsumer<Integer, String> hook) {
        this.beforeRecordCasHook = hook;
    }

    /**
     * 处理单条记录。整个生命周期读锁内完成解密与新加密，源/目标版本在该瞬间稳定。
     * 解密失败（含完整性失败）与 CAS 冲突都计入 failed 并保留原密文，不抛出到批处理外。
     */
    private void processOne(EncryptedRecord record, KeyVersion source, KeyVersion target,
                            MutableProgress progress) {
        String oldCipher;
        int recordVersion;
        synchronized (record) {
            recordVersion = record.getKeyVersion();
            oldCipher = record.getCipherText();
        }

        // 幂等判定：只有仍引用源版本的记录需要迁
        if (recordVersion != source.getVersion()) {
            progress.totalSkipped++;
            progress.runSkipped++;
            auditLogger.log("MIGRATE_SKIP", recordVersion, "ALLOWED",
                    "record " + record.getId() + " already on version " + recordVersion);
            return;
        }

        var hook = beforeRecordCasHook;
        if (hook != null) {
            hook.accept(source.getVersion(), record.getId());
        }

        try {
            // oldCipher 是进入本方法时捕获的快照；解密与 CAS 之间记录可能已被并发改写
            String newCipher = keyLifecycleManager.withReadLock(() -> {
                CipherPayload oldPayload = cipherService.decode(oldCipher);
                KeyVersion decryptKey = keyLifecycleManager.requireVersionForDecrypt(source.getVersion());
                byte[] plain = cipherService.decrypt(decryptKey, oldPayload);
                CipherPayload fresh = cipherService.encrypt(
                        keyLifecycleManager.requireVersion(target.getVersion()), plain);
                return cipherService.encode(fresh);
            });

            boolean swapped = recordStore.compareAndUpdate(
                    record, source.getVersion(), oldCipher, target.getVersion(), newCipher);
            if (swapped) {
                progress.totalMigrated++;
                progress.runMigrated++;
                auditLogger.log("MIGRATE", target.getVersion(), "ALLOWED",
                        "record " + record.getId() + " re-encrypted "
                                + source.getVersion() + "->" + target.getVersion());
            } else {
                progress.totalFailed++;
                progress.runFailed++;
                progress.lastIssue = "record " + record.getId() + " changed concurrently";
                auditLogger.log("MIGRATE", source.getVersion(), "REJECTED",
                        "CAS conflict on record " + record.getId());
            }
        } catch (RuntimeException e) {
            // 解密/完整性失败：原样保留旧密文，计入失败，迁移整体不会因此 corrupt 任何数据
            progress.totalFailed++;
            progress.runFailed++;
            progress.lastIssue = "record " + record.getId() + " failed: " + e.getClass().getSimpleName();
            auditLogger.log("MIGRATE", source.getVersion(), "REJECTED",
                    "record " + record.getId() + " processing failed");
        }
    }

    /** 可变迁移状态；仅在批处理线程内更新，snapshot 在锁内导出。 */
    private static final class MutableProgress {
        final String migrationId;
        final int fromVersion;
        final int toVersion;
        final long totalAtStart;
        final Instant startedAt;
        volatile MigrationStatus status = MigrationStatus.PAUSED;
        // 跨多次续跑累计的计数
        volatile long totalMigrated;
        volatile long totalSkipped;
        volatile long totalFailed;
        // 仅本次调用有效的计数（进入时清零）
        long runMigrated;
        long runSkipped;
        long runFailed;
        volatile String checkpointId;
        volatile Instant finishedAt;
        volatile String lastIssue;
        volatile boolean interrupted;

        MutableProgress(String migrationId, int fromVersion, int toVersion, int totalAtStart) {
            this.migrationId = migrationId;
            this.fromVersion = fromVersion;
            this.toVersion = toVersion;
            this.totalAtStart = totalAtStart;
            this.startedAt = Instant.now();
        }

        MigrationProgress snapshot(long remainingByVersion) {
            return new MigrationProgress(migrationId, fromVersion, toVersion, status.name(),
                    totalAtStart, totalMigrated, totalSkipped, totalFailed, remainingByVersion,
                    checkpointId, startedAt, finishedAt, lastIssue);
        }
    }
}
