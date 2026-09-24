package com.github.lisama569.cryptokeylifecyclejava.tests;

import org.springframework.test.annotation.DirtiesContext;
import com.github.lisama569.cryptokeylifecyclejava.error.FailureReason;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationProgress;
import com.github.lisama569.cryptokeylifecyclejava.service.CryptoService;
import com.github.lisama569.cryptokeylifecyclejava.service.KeyAdminService;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecord;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecordStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 历史数据迁移集成测试：吊销前置引用检查、分批中断续跑、幂等、进度可核验。
 * 每个类独立 ApplicationContext，避免版本序号相互影响。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class MigrationIntegrationTest {

    private static final Logger testLog = LoggerFactory.getLogger("KEY_LIFECYCLE_TEST");

    @Autowired
    private CryptoService cryptoService;
    @Autowired
    private KeyAdminService keyAdminService;
    @Autowired
    private EncryptedRecordStore recordStore;

    private int currentVersion() {
        return keyAdminService.versions().stream()
                .filter(v -> v.current()).findFirst().orElseThrow().version();
    }

    private int seedDataUnderOldVersion(int oldVersion, int count) {
        for (int i = 0; i < count; i++) {
            // id 零填充，保证字典序与数字序一致，迁移扫描顺序稳定
            cryptoService.encrypt(String.format("q-%d-%04d", oldVersion, i),
                    "payload-" + oldVersion + "-" + i);
        }
        return count;
    }

    @Test
    @DisplayName("有引用时吊销被 REFERENCES_REMAIN 拒绝；迁移完成后可吊销，历史明文仍可经新版本读取")
    void revokeBlockedUntilMigrationCompletes() {
        int v1 = currentVersion();
        seedDataUnderOldVersion(v1, 25);
        int v2 = keyAdminService.rotate().getVersion();

        KeyLifecycleException ex = assertThrows(KeyLifecycleException.class,
                () -> keyAdminService.revoke(v1));
        assertEquals(FailureReason.REFERENCES_REMAIN, ex.getReason());
        testLog.info("op=REVOKE keyVersion={} decision=REJECTED reason='{} (25 records)'", v1, ex.getReason());

        MigrationProgress done = keyAdminService.migrate(v1, 10, null, null);
        assertEquals("COMPLETED", done.status());
        assertEquals(25, done.migrated());
        assertEquals(0, done.remainingByVersion(), "实时核验：源版本引用必须清零");

        // 明文含义不变，但记录版本全部切到新版本
        for (int i = 0; i < 25; i++) {
            EncryptedRecord record = recordStore.require(String.format("q-%d-%04d", v1, i));
            assertEquals(v2, record.getKeyVersion());
            assertEquals("payload-" + v1 + "-" + i, cryptoService.decrypt(String.format("q-%d-%04d", v1, i)));
        }

        keyAdminService.revoke(v1);
        testLog.info("op=REVOKE keyVersion={} decision=ALLOWED reason='migration drained references'", v1);

        // 旧版本吊销后，历史数据因为已迁到 v2，仍可解密
        assertEquals("payload-" + v1 + "-0", cryptoService.decrypt(String.format("q-%d-%04d", v1, 0)));
    }

    @Test
    @DisplayName("分批迁移：maxBatches 限制下 PAUSED + checkpoint；凭 migrationId 续跑到 COMPLETED")
    void batchedMigrationPausesAndResumes() {
        int oldV = currentVersion();
        int total = seedDataUnderOldVersion(oldV, 25);
        int targetV = keyAdminService.rotate().getVersion();

        // 第一批：batchSize=10, maxBatches=1 -> 最多迁 10 条，应 PAUSED
        MigrationProgress first = keyAdminService.migrate(oldV, 10, 1, null);
        String migrationId = first.migrationId();
        assertEquals("PAUSED", first.status());
        assertEquals(10, first.migrated());
        assertEquals(15, first.remainingByVersion(), "进度核验：剩余引用实时计数");
        assertNotNull(first.checkpointId());
        testLog.info("op=MIGRATE keyVersion={} decision=PAUSED reason='batch 1/?, migrated=10, checkpoint={}'",
                oldV, first.checkpointId());

        // 续跑一批：又迁 10 条
        MigrationProgress second = keyAdminService.migrate(oldV, 10, 1, migrationId);
        assertEquals("PAUSED", second.status());
        assertEquals(20, second.migrated(), "migrated 跨调用累计");
        assertEquals(5, second.remainingByVersion());

        // 跑到完成（maxBatches 缺省 = 无限）
        MigrationProgress finished = keyAdminService.migrate(oldV, 10, null, migrationId);
        assertEquals("COMPLETED", finished.status());
        assertEquals(total, finished.migrated());
        assertEquals(0, finished.remainingByVersion());
        assertEquals(targetV, finished.toVersion());
        testLog.info("op=MIGRATE keyVersion={} decision=COMPLETED reason='all {} records now on version {}'",
                oldV, total, targetV);

        for (int i = 0; i < total; i++) {
            assertEquals(targetV, recordStore.require(String.format("q-%d-%04d", oldV, i)).getKeyVersion());
            assertEquals("payload-" + oldV + "-" + i, cryptoService.decrypt(String.format("q-%d-%04d", oldV, i)));
        }
    }

    @Test
    @DisplayName("迁移幂等：完成后用同一 migrationId / 新 migrationId 再跑，全部 SKIPPED，明文与版本不变")
    void migrationIsIdempotent() {
        int oldV = currentVersion();
        int total = seedDataUnderOldVersion(oldV, 15);
        int targetV = keyAdminService.rotate().getVersion();

        MigrationProgress done = keyAdminService.migrate(oldV, 5, null, null);
        assertEquals("COMPLETED", done.status());

        // 用同一 migrationId 续跑（已完成的也允许再核验一遍）
        MigrationProgress rerun = keyAdminService.migrate(oldV, 5, null, done.migrationId());
        assertEquals(total, rerun.skipped(), "重跑时所有记录都应跳过");
        assertEquals(total, rerun.migrated(), "已迁移计数不重复累加");
        assertEquals(0, rerun.remainingByVersion());

        // 全新 migration 再跑一次：全部跳过，不产生任何版本变化
        MigrationProgress rerun2 = keyAdminService.migrate(oldV, 5, null, null);
        assertEquals("COMPLETED", rerun2.status());
        assertEquals(0, rerun2.migrated());
        assertEquals(total, rerun2.skipped());

        for (int i = 0; i < total; i++) {
            EncryptedRecord record = recordStore.require(String.format("q-%d-%04d", oldV, i));
            assertEquals(targetV, record.getKeyVersion(), "重复迁移不得改变记录状态");
            assertEquals("payload-" + oldV + "-" + i, cryptoService.decrypt(String.format("q-%d-%04d", oldV, i)),
                    "重复迁移不得改变明文含义");
        }
        testLog.info("op=MIGRATE keyVersion={} decision=COMPLETED reason='idempotent rerun: {} skipped, 0 changed'",
                oldV, total);
    }
}
