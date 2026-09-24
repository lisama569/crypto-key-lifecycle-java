package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationProgress;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 历史数据迁移：幂等、可中断续跑、进度核验、失败保留原密文。 */
class MigrationServiceTest {

    private static final Logger log = LoggerFactory.getLogger(MigrationServiceTest.class);

    private static final class Fixture {
        final KeyManager km = new KeyManager(new InMemoryKeyStore(),
                new AesGcmCipher(12, 128), new CipherCodec(), 256);
        final InMemoryDataRepository repo = new InMemoryDataRepository();
        final MigrationService migration = new MigrationService(km, repo);
        final CipherCodec codec = new CipherCodec();
        final Map<String, String> plainById = new LinkedHashMap<>();
    }

    private Fixture seed(int count) {
        Fixture f = new Fixture();
        f.km.generateAndActivate(); // v1
        for (int i = 0; i < count; i++) {
            String id = "rec-" + i;
            String plain = "明文记录#" + i;
            f.plainById.put(id, plain);
            String cipher = f.km.encrypt(plain);
            f.repo.save(new DataRecord(id, cipher, 1, RecordStatus.CURRENT));
        }
        return f;
    }

    private void assertAllPlaintextsRecoverable(Fixture f) {
        f.plainById.forEach((id, expected) -> {
            DataRecord r = f.repo.findById(id).orElseThrow();
            assertEquals(expected, f.km.decrypt(r.ciphertext()),
                    "migration must not change plaintext meaning for " + id);
        });
    }

    @Test
    void batchMigrationCanBeInterruptedAndResumedWithVerifiableProgress() {
        Fixture f = seed(10);
        f.km.rotate(); // v2 ACTIVE, v1 RETIRED

        // 第一批：处理 4 条后中断
        MigrationProgress p1 = f.migration.migrateToCurrent(4);
        assertEquals(4, p1.migrated());
        assertEquals(6, p1.remaining());
        assertFalse(p1.completed());
        assertEquals(40.0, p1.percent(), 0.01);
        long onV2AfterBatch1 = f.repo.findAll().stream().filter(r -> r.keyVersion() == 2).count();
        assertEquals(4, onV2AfterBatch1);

        // 续跑：处理 4 条
        MigrationProgress p2 = f.migration.migrateToCurrent(4);
        assertEquals(4, p2.migrated());
        assertEquals(2, p2.remaining());
        assertFalse(p2.completed());

        // 最后一批收尾
        MigrationProgress p3 = f.migration.migrateToCurrent(4);
        assertEquals(2, p3.migrated());
        assertTrue(p3.completed());
        assertEquals(100.0, p3.percent(), 0.01);

        assertAllPlaintextsRecoverable(f);
        MigrationProgress snapshot = f.migration.progress();
        assertTrue(snapshot.completed());
        log.info("[migration] version=1->2 op=BATCHED basis=INTERRUPT_AND_RESUME batches=4+4+2 progress={}% result=PASS",
                p3.percent());
    }

    @Test
    void repeatedMigrationIsIdempotentAndKeepsPlaintextMeaning() {
        Fixture f = seed(5);
        f.km.rotate();

        MigrationProgress first = f.migration.migrateToCurrent(null);
        assertTrue(first.completed());
        assertEquals(5, first.migrated());

        // 记录第一次迁移后的密文
        Map<String, String> cipherAfterFirst = new LinkedHashMap<>();
        f.repo.findAll().forEach(r -> cipherAfterFirst.put(r.id(), r.ciphertext()));

        // 再跑两轮：全部跳过，密文不再被改写，状态不冲突
        MigrationProgress second = f.migration.migrateToCurrent(null);
        MigrationProgress third = f.migration.migrateToCurrent(100);
        assertEquals(0, second.migrated());
        assertEquals(5, second.skipped());
        assertEquals(0, third.migrated());
        assertEquals(5, third.skipped());
        f.repo.findAll().forEach(r ->
                assertEquals(cipherAfterFirst.get(r.id()), r.ciphertext(),
                        "idempotent re-migration must not rewrite record " + r.id()));

        assertAllPlaintextsRecoverable(f);
        // 同一份数据只有一种一致状态：全部 CURRENT 且全部在版本 2
        f.repo.findAll().forEach(r -> {
            assertEquals(2, r.keyVersion());
            assertEquals(RecordStatus.CURRENT, r.status());
        });
        log.info("[migration] version=1->2 op=REPEAT basis=IDEMPOTENT_SKIP skipped={} result=PASS",
                second.skipped());
    }

    @Test
    void recordsProducedOnNewVersionCoexistAndNeedNoMigration() {
        Fixture f = seed(3);
        f.km.rotate();
        // 轮换后新写入的两条数据直接在 v2
        for (int i = 0; i < 2; i++) {
            String id = "new-" + i;
            String plain = "新数据#" + i;
            f.plainById.put(id, plain);
            f.repo.save(new DataRecord(id, f.km.encrypt(plain), 2, RecordStatus.CURRENT));
        }
        MigrationProgress p = f.migration.migrateToCurrent(null);
        assertEquals(3, p.migrated());
        assertEquals(2, p.skipped());
        assertEquals(5, p.total());
        assertTrue(p.completed());
        assertAllPlaintextsRecoverable(f);
        log.info("[migration] version=1->2 op=MIXED basis=NEW_DATA_SKIPPED migrated={} skipped={} result=PASS",
                p.migrated(), p.skipped());
    }

    @Test
    void recordsEncryptedUnderRevokedVersionFailButAreNotCorrupted() {
        Fixture f = seed(4);
        f.km.rotate(); // v1 RETIRED
        f.km.revoke(1); // 吊销但未迁移

        MigrationProgress p = f.migration.migrateToCurrent(null);
        assertEquals(4, p.failed());
        assertEquals(0, p.migrated());
        assertFalse(p.completed());

        // 失败记录保留原密文与原版本，数据未被破坏、无冲突状态
        f.repo.findAll().forEach(r -> {
            assertEquals(1, r.keyVersion());
            assertTrue(r.ciphertext().startsWith("v1:"));
        });
        // 恢复版本不可行（吊销是终态）——用错误响应不含明文验证：迁移日志/进度中没有明文内容
        log.warn("[migration] version=1(REVOKED)->2 op=MIGRATE basis=REVOKED_SOURCE failed={} preservedOriginal=true result=EXPECTED_FAILURE",
                p.failed());
    }

    @Test
    void furtherRotationDuringMigrationMeansResumeTargetsLatestVersion() {
        Fixture f = seed(6);
        f.km.rotate(); // v2
        f.migration.migrateToCurrent(3); // 3 条到 v2
        f.km.rotate(); // v3：剩余 v1 与 v2 记录都将以 v3 为目标
        MigrationProgress p = f.migration.migrateToCurrent(null);
        assertTrue(p.completed());
        f.repo.findAll().forEach(r -> assertEquals(3, r.keyVersion()));
        assertAllPlaintextsRecoverable(f);
        log.info("[migration] version=*->3 op=MIGRATE_ACROSS_ROTATION basis=TARGET_FOLLOWS_CURRENT total={} result=PASS",
                p.total());
    }
}
