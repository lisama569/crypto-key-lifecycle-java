package com.github.lisama569.cryptokeylifecyclejava.service;

import com.github.lisama569.cryptokeylifecyclejava.audit.AuditLogger;
import com.github.lisama569.cryptokeylifecyclejava.config.KeyLifecycleProperties;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyLifecycleManager;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyVersionInfo;
import com.github.lisama569.cryptokeylifecyclejava.migration.HistoricalDataMigrator;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationProgress;
import org.springframework.stereotype.Service;

import java.util.List;

/** 管理面服务：轮换、吊销与历史迁移的用例入口。 */
@Service
public class KeyAdminService {

    private final KeyLifecycleManager keyLifecycleManager;
    private final HistoricalDataMigrator migrator;
    private final KeyLifecycleProperties properties;
    private final AuditLogger auditLogger;

    public KeyAdminService(KeyLifecycleManager keyLifecycleManager,
                           HistoricalDataMigrator migrator,
                           KeyLifecycleProperties properties,
                           AuditLogger auditLogger) {
        this.keyLifecycleManager = keyLifecycleManager;
        this.migrator = migrator;
        this.properties = properties;
        this.auditLogger = auditLogger;
    }

    public KeyVersion rotate() {
        KeyVersion rotated = keyLifecycleManager.rotate();
        auditLogger.log("ADMIN_ROTATE", rotated.getVersion(), "ALLOWED", "rotation request completed");
        return rotated;
    }

    public void revoke(int version) {
        keyLifecycleManager.revokeVersion(version);
        auditLogger.log("ADMIN_REVOKE", version, "ALLOWED", "revocation request completed");
    }

    public List<KeyVersionInfo> versions() {
        return keyLifecycleManager.listVersions();
    }

    /**
     * 启动/续跑历史迁移。batchSize 缺省取配置；maxBatches 缺省跑到完成。
     */
    public MigrationProgress migrate(int fromVersion, Integer batchSize, Integer maxBatches, String resumeId) {
        int batch = batchSize == null ? properties.getMigrationBatchSize() : batchSize;
        int batches = maxBatches == null ? -1 : maxBatches;
        return migrator.migrate(fromVersion, batch, batches, resumeId);
    }

    public MigrationProgress migrationProgress(String migrationId) {
        return migrator.getProgress(migrationId);
    }

    public void interruptMigration(String migrationId) {
        migrator.interrupt(migrationId);
    }
}
