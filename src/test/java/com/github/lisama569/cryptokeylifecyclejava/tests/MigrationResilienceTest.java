package com.github.lisama569.cryptokeylifecyclejava.tests;

import org.springframework.test.annotation.DirtiesContext;
import com.github.lisama569.cryptokeylifecyclejava.error.FailureReason;
import com.github.lisama569.cryptokeylifecyclejava.error.IntegrityVerificationException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownKeyVersionException;
import com.github.lisama569.cryptokeylifecyclejava.migration.HistoricalDataMigrator;
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

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 迁移韧性与数据安全测试：
 * <ul>
 *   <li>外部中断 → PAUSED，凭 migrationId 续跑完成；</li>
 *   <li>迁移中并发改写某记录 → CAS 冲突，FAILED 计数且原数据可继续读，重跑收敛；</li>
 *   <li>存储密文被直接篡改 → 该条 INTEGRITY_FAILURE 计入失败，其余记录照常迁移，服务不受影响；</li>
 *   <li>吊销后解密被 REVOKED_VERSION 拒绝，原因与完整性失败可区分。</li>
 * </ul>
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class MigrationResilienceTest {

    private static final Logger testLog = LoggerFactory.getLogger("KEY_LIFECYCLE_TEST");

    @Autowired private CryptoService cryptoService;
    @Autowired private KeyAdminService keyAdminService;
    @Autowired private EncryptedRecordStore recordStore;
    @Autowired private HistoricalDataMigrator migrator;

    private int keyLifecycleCurrentVersion() {
        return keyAdminService.versions().stream()
                .filter(v -> v.current()).findFirst().orElseThrow().version();
    }

    @org.junit.jupiter.api.BeforeEach
    void clearHooks() {
        // 共享上下文时前序测试可能留下钩子，每个测试开始前必须清空
        migrator.setBeforeRecordCasHook(null);
    }

    private void seed(int count) {
        for (int i = 0; i < count; i++) {
            cryptoService.encrypt(String.format("w-%04d", i), "payload-" + i);
        }
    }

    @Test
    @DisplayName("中断迁移：钩子在处理中途触发 interrupt → PAUSED + checkpoint；续跑到 COMPLETED")
    void interruptAndResume() {
        int total = 40;
        int oldV = keyLifecycleCurrentVersion();
        seed(total);                          // 数据产生于当前版本
        int targetV = keyAdminService.rotate().getVersion();

        // 第一批先迁 10 条拿到 migrationId
        MigrationProgress first = keyAdminService.migrate(oldV, 10, 1, null);
        String id = first.migrationId();
        assertEquals(10, first.migrated());

        // 通过钩子在第 15 条记录处理前请求中断：确定性、无睡眠竞态
        AtomicReference<String> midMigrationId = new AtomicReference<>(id);
        migrator.setBeforeRecordCasHook((fromVersion, recordId) -> {
            if ("w-0014".equals(recordId)) {
                keyAdminService.interruptMigration(midMigrationId.get());
            }
        });
        MigrationProgress interrupted = keyAdminService.migrate(oldV, 100, null, id);
        migrator.setBeforeRecordCasHook(null);

        assertEquals("PAUSED", interrupted.status());
        // r-0010..r-0014 共 5 条处理后，在 r-0014 上请求中断；r-0014 本身已处理完
        assertTrue(interrupted.migrated() >= 14 && interrupted.migrated() < total,
                "中断位置应在中途，实际 migrated=" + interrupted.migrated());
        assertNotNull(interrupted.checkpointId());
        testLog.info("op=MIGRATE keyVersion={} decision=PAUSED reason='interrupted at checkpoint {}'",
                oldV, interrupted.checkpointId());

        MigrationProgress done = keyAdminService.migrate(oldV, 100, null, id);
        assertEquals("COMPLETED", done.status());
        assertEquals(total, done.migrated());
        for (int i = 0; i < total; i++) {
            String rid = String.format("w-%04d", i);
            assertEquals(targetV, recordStore.require(rid).getKeyVersion());
            assertEquals("payload-" + i, cryptoService.decrypt(rid));
        }
        testLog.info("op=MIGRATE keyVersion={} decision=COMPLETED reason='resumed after interrupt'", oldV);
    }

    @Test
    @DisplayName("确定性 CAS 冲突：迁移读快照后并发改写记录 → 该条 CAS 失败计入 failed，明文仍可读；重跑收敛")
    void deterministicCasConflictDuringMigration() {
        int oldV = keyLifecycleCurrentVersion();
        seed(5);
        int targetV = keyAdminService.rotate().getVersion();
        migrator.setBeforeRecordCasHook((fromVersion, recordId) -> {
            if ("w-0002".equals(recordId)) {
                // 模拟并发重写：仍用源版本密钥加密同一明文（随机 IV 得到不同密文），
                // 版本号不变但密文已不是迁移线程捕获的快照，CAS 必须失败
                EncryptedRecord rec = recordStore.require("w-0002");
                String concurrentCipher = cryptoService.encryptWithVersion(oldV, "payload-2");
                recordStore.replace(rec, oldV, concurrentCipher);
            }
        });

        MigrationProgress progress = keyAdminService.migrate(oldV, 100, null, null);
        migrator.setBeforeRecordCasHook(null);
        assertEquals("FAILED", progress.status(), "存在 CAS 冲突时整体必须标记 FAILED");
        assertEquals(1, progress.failed(), "恰好 1 条冲突");
        assertEquals(4, progress.migrated(), "其余 4 条成功迁移");

        // 冲突记录未被迁移线程覆盖：版本仍是 oldV，明文含义为并发写入者写入的 payload-3
        EncryptedRecord victim = recordStore.require("w-0002");
        assertEquals(oldV, victim.getKeyVersion(), "CAS 失败不得改动记录版本");
        assertEquals("payload-2", cryptoService.decrypt("w-0002"), "并发重写未改变明文含义");

        // 重跑：滞留重扫发现 w-0002 仍引用源版本 → 迁走到目标版本，最终 COMPLETED
        MigrationProgress rerun = keyAdminService.migrate(oldV, 100, null, progress.migrationId());
        assertEquals("COMPLETED", rerun.status());
        assertEquals(5, rerun.migrated(), "累计迁移数 = 首轮 4 + 重跑滞留 1");
        assertEquals(targetV, recordStore.require("w-0002").getKeyVersion());
        assertEquals("payload-2", cryptoService.decrypt("w-0002"));
        assertEquals(0, rerun.remainingByVersion(), "源版本引用实时核验清零");
        testLog.info("op=MIGRATE_CONFLICT keyVersion={} decision=REJECTED "
                + "reason='CAS stale on w-0002; stranded record migrated on rerun, no torn state'", oldV);
    }

    @Test
    @DisplayName("存储密文被直接篡改：迁移该条失败，整体 FAILED；其它记录不受影响且服务可用")
    void tamperedRecordFailsMigrationButOthersSucceed() {
        int oldV = keyLifecycleCurrentVersion();
        seed(5);
        keyAdminService.rotate().getVersion();

        // 直接破坏 r-0002：翻转密文段中间位置的字符（保持可解析，GCM 标签必然失效）
        EncryptedRecord tampered = recordStore.require("w-0002");
        String cipher = tampered.getCipherText();
        int dot = cipher.indexOf('.');
        int mid = dot + 5;
        char c = cipher.charAt(mid);
        char flipped = c == 'A' ? 'B' : 'A';
        String corrupted = cipher.substring(0, mid) + flipped + cipher.substring(mid + 1);
        assertNotEquals(cipher, corrupted);
        recordStore.replace(tampered, oldV, corrupted);

        MigrationProgress progress = keyAdminService.migrate(oldV, 100, null, null);
        assertEquals("FAILED", progress.status());
        assertEquals(1, progress.failed(), "恰好被篡改的 1 条计入失败");
        assertEquals(4, progress.migrated(), "其余 4 条正常迁移");
        assertEquals(oldV, recordStore.require("w-0002").getKeyVersion(), "失败记录原状保留");

        // 直接解密被篡改记录：必须 INTEGRITY_FAILURE，且与 REVOKED_VERSION 可区分
        IntegrityVerificationException ex = assertThrows(IntegrityVerificationException.class,
                () -> cryptoService.decrypt("w-0002"));
        assertEquals(FailureReason.INTEGRITY_FAILURE, ex.getReason());
        assertFalse(ex.getMessage().contains("payload-2"), "异常文案不得含明文");
        testLog.info("op=MIGRATE keyVersion={} decision=FAILED reason='1 INTEGRITY_FAILURE, 4 migrated'", oldV);
    }

    @Test
    @DisplayName("吊销后任何声称该版本的解密 → REVOKED_VERSION；服务仍持续处理新版本请求")
    void revokedVersionDecryptRejectedButServiceAlive() {
        int v1 = keyLifecycleCurrentVersion();
        cryptoService.encrypt("doomed", "doomed-secret");
        int v2 = keyAdminService.rotate().getVersion();

        assertEquals("doomed-secret", cryptoService.decrypt("doomed"), "RETIRED 保留期内可解");

        // 当前 ENABLED 版本不能直接吊销
        KeyLifecycleException cannotRevokeCurrent = assertThrows(KeyLifecycleException.class,
                () -> keyAdminService.revoke(v2));
        assertEquals(FailureReason.INVALID_VERSION_STATE, cannotRevokeCurrent.getReason());

        // 迁走数据 → 吊销 v1 → 声称 v1 的密文在状态检查阶段即被拒绝（先于 GCM）
        MigrationProgress done = keyAdminService.migrate(v1, 10, null, null);
        assertEquals("COMPLETED", done.status());
        keyAdminService.revoke(v1);

        KeyLifecycleException revoked = assertThrows(KeyLifecycleException.class,
                () -> cryptoService.decryptTransient(buildFakeV1Cipher()));
        assertEquals(FailureReason.REVOKED_VERSION, revoked.getReason());
        testLog.info("op=DECRYPT keyVersion={} decision=REJECTED reason='{}'", v1, revoked.getReason());

        // 已迁移数据经新版本仍可读；新版本写入正常：服务持续可用
        assertEquals("doomed-secret", cryptoService.decrypt("doomed"));
        cryptoService.encrypt("alive", "still-serving");
        assertEquals("still-serving", cryptoService.decrypt("alive"));
        testLog.info("op=ENCRYPT keyVersion={} decision=ALLOWED reason='service alive after revocation'", v2);
    }

    @Test
    @DisplayName("非法迁移请求：源版本未轮换 → MIGRATION_NOT_RUNNABLE；源版本不存在 → UNKNOWN_VERSION")
    void invalidMigrationRequests() {
        int current = keyAdminService.rotate().getVersion();
        KeyLifecycleException notRetired = assertThrows(KeyLifecycleException.class,
                () -> keyAdminService.migrate(current, 10, null, null));
        assertEquals(FailureReason.MIGRATION_NOT_RUNNABLE, notRetired.getReason());

        KeyLifecycleException unknown = assertThrows(KeyLifecycleException.class,
                () -> keyAdminService.migrate(4242, 10, null, null));
        assertEquals(FailureReason.UNKNOWN_VERSION, unknown.getReason());
        assertTrue(unknown instanceof UnknownKeyVersionException);
        testLog.info("op=MIGRATE keyVersion=- decision=REJECTED reason='source not retired / unknown version'");
    }

    private static String buildFakeV1Cipher() {
        // 格式合法：IV 必须是 12 字节（base64url 无填充恰好 16 字符），密文段 > 16 字节；
        // 状态拒绝（REVOKED）必须先于 GCM 校验发生
        String iv = "AAAAAAAAAAAAAAA_";              // 16 chars = 12 bytes
        String body = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // > 16 字节
        return "v1:1 " + iv + "." + body;
    }
}
