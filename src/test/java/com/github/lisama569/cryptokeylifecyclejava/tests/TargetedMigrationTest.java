package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionLifecycleService;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import com.github.lisama569.cryptokeylifecyclejava.migration.SourceCleanupProgress;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 按来源版本定向清理：分批、中断续跑、幂等、多代独立收敛，数据量千条级。 */
class TargetedMigrationTest {

    private static final Logger log = LoggerFactory.getLogger(TargetedMigrationTest.class);

    private KeyManager km;
    private InMemoryDataRepository repo;
    private MigrationService migration;
    private VersionLifecycleService lifecycle;

    @BeforeEach
    void setUp() {
        km = new KeyManager(new InMemoryKeyStore(), new AesGcmCipher(12, 128), new CipherCodec(), 256);
        repo = new InMemoryDataRepository();
        migration = new MigrationService(km, repo);
        lifecycle = new VersionLifecycleService(km, repo);
        km.generateAndActivate(); // v1 ACTIVE
    }

    private void saveRecords(String prefix, int count, int version) {
        for (int i = 0; i < count; i++) {
            repo.save(new DataRecord(prefix + "-" + i, km.encrypt(prefix + "-" + i),
                    version, RecordStatus.CURRENT));
        }
    }

    @Test
    void targetedCleanupIsBatchedResumableAndIdempotentAtThousandScale() {
        int total = 1200;
        saveRecords("t", total, 1);
        km.rotate(); // v1 RETIRED(1200 refs), v2 ACTIVE

        // 分批中断续跑：500 + 500 + 余量
        SourceCleanupProgress p1 = migration.migrateFromVersion(1, 500);
        assertEquals(500, p1.migrated());
        assertEquals(700, p1.remaining());
        assertEquals(1200, p1.sourceTotal());
        assertEquals(700, lifecycle.statsFor(1).referenceCount(), "stats track cleanup in real time");

        SourceCleanupProgress p2 = migration.migrateFromVersion(1, 500);
        assertEquals(500, p2.migrated());
        assertEquals(200, p2.remaining());

        SourceCleanupProgress p3 = migration.migrateFromVersion(1, 500);
        assertEquals(200, p3.migrated());
        assertEquals(0, p3.remaining());
        assertTrue(p3.completed());
        assertEquals(0, lifecycle.statsFor(1).referenceCount(), "references converge to exactly zero");

        // 幂等：重复执行不再改动任何记录，明文含义不变
        Map<String, String> before = new HashMap<>();
        repo.findAll().forEach(r -> before.put(r.id(), r.ciphertext()));
        SourceCleanupProgress p4 = migration.migrateFromVersion(1, null);
        assertEquals(0, p4.migrated());
        assertEquals(0, p4.failed());
        assertTrue(p4.completed());
        repo.findAll().forEach(r -> {
            assertEquals(before.get(r.id()), r.ciphertext(), "idempotent rerun must not rewrite");
            assertEquals(2, r.keyVersion());
            assertEquals("t-" + r.id().substring(2), km.decrypt(r.ciphertext()));
        });
        log.info("[cleanup] version=1->2 op=CLEANUP basis=BATCHED_RESUMABLE_IDEMPOTENT total={} result=PASS", total);
    }

    @Test
    void targetedCleanupLeavesOtherGenerationsUntouched() {
        saveRecords("g1", 300, 1);
        km.rotate(); // v2 ACTIVE
        saveRecords("g2", 400, 2);
        km.rotate(); // v3 ACTIVE; v1:300 refs, v2:400 refs

        // 只清 v1：v2 的记录一条不动
        SourceCleanupProgress p = migration.migrateFromVersion(1, null);
        assertEquals(300, p.migrated());
        assertTrue(p.completed());
        assertEquals(0, lifecycle.statsFor(1).referenceCount());
        assertEquals(400, lifecycle.statsFor(2).referenceCount(), "other generations untouched");
        assertEquals(400, repo.findAll().stream().filter(r -> r.keyVersion() == 2).count());

        // 再独立清 v2
        SourceCleanupProgress p2 = migration.migrateFromVersion(2, null);
        assertEquals(400, p2.migrated());
        assertTrue(p2.completed());
        assertEquals(0, lifecycle.statsFor(2).referenceCount());

        // 全部收敛到 v3，明文含义保持
        repo.findAll().forEach(r -> {
            assertEquals(3, r.keyVersion());
            String expected = r.id().startsWith("g1") ? "g1-" + r.id().substring(3)
                    : "g2-" + r.id().substring(3);
            assertEquals(expected, km.decrypt(r.ciphertext()));
        });
        log.info("[cleanup] op=CLEANUP basis=MULTI_GENERATION_CONVERGE generations=2 total=700 result=PASS");
    }

    @Test
    void targetedCleanupRejectsActiveAndUnknownSource() {
        km.rotate(); // v2 ACTIVE
        KeyConflictException active = assertThrows(KeyConflictException.class,
                () -> migration.migrateFromVersion(2, null));
        assertEquals("KEY_STATE_CONFLICT", active.reasonCode());
        UnknownVersionException unknown = assertThrows(UnknownVersionException.class,
                () -> migration.migrateFromVersion(77, null));
        assertEquals("UNKNOWN_VERSION", unknown.reasonCode());
        log.info("[cleanup] op=CLEANUP basis=SOURCE_VALIDATION reason=KEY_STATE_CONFLICT/UNKNOWN_VERSION result=REJECTED");
    }

    @Test
    void cleanupOfRevokedGenerationFailsIsolatedAndPreservesCiphertext() {
        saveRecords("d", 5, 1);
        km.rotate();
        km.revoke(1); // 强制吊销（revoke 无门禁），v1 数据无法再解密

        SourceCleanupProgress p = migration.migrateFromVersion(1, null);
        assertEquals(0, p.migrated());
        assertEquals(5, p.failed());
        assertEquals(5, p.remaining());
        assertTrue(!p.completed());
        assertEquals(5, lifecycle.statsFor(1).referenceCount(),
                "failed records keep referencing the source version");
        repo.findAll().forEach(r -> assertEquals(1, r.keyVersion(),
                "original ciphertext preserved on failure"));
        log.info("[cleanup] version=1(REVOKED) op=CLEANUP basis=REVOKED_SOURCE failed=5 result=EXPECTED_FAILURE");
    }
}
