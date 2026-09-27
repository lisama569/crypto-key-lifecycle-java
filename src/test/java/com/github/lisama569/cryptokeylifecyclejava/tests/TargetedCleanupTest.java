package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.decommission.MaintenanceLock;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceService;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import com.github.lisama569.cryptokeylifecyclejava.migration.TargetedMigrationProgress;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 按来源版本定向清理：中断续跑、幂等、多代独立收敛、失败隔离。 */
class TargetedCleanupTest {

    private static final Logger log = LoggerFactory.getLogger(TargetedCleanupTest.class);

    private static final class Fixture {
        final KeyManager km = new KeyManager(new InMemoryKeyStore(),
                new AesGcmCipher(12, 128), new CipherCodec(), 256);
        final InMemoryDataRepository repo = new InMemoryDataRepository();
        final MaintenanceLock lock = new MaintenanceLock();
        final MigrationService migration = new MigrationService(km, repo, lock);
        final VersionReferenceService refs = new VersionReferenceService(km, repo, lock);
        final Map<String, String> plainById = new LinkedHashMap<>();
    }

    private void seedVersion(Fixture f, int version, int count) {
        for (int i = 0; i < count; i++) {
            String id = "v" + version + "-" + i;
            String plain = "明文v" + version + "#" + i;
            f.plainById.put(id, plain);
            f.repo.save(new DataRecord(id, f.km.encrypt(plain), version, RecordStatus.CURRENT));
        }
    }

    private void assertAllPlaintextsRecoverable(Fixture f) {
        f.plainById.forEach((id, expected) ->
                assertEquals(expected, f.km.decrypt(f.repo.findById(id).orElseThrow().ciphertext()),
                        "targeted cleanup must not change plaintext for " + id));
    }

    @Test
    void targetedCleanupOfThousandRecordsCanBeInterruptedAndResumed() {
        Fixture f = new Fixture();
        f.km.generateAndActivate(); // v1
        seedVersion(f, 1, 1000);
        f.km.rotate(); // v2

        TargetedMigrationProgress b1 = f.migration.migrateVersion(1, 300);
        assertEquals(1000, b1.total());
        assertEquals(300, b1.migrated());
        assertEquals(700, b1.remaining());
        assertFalse(b1.completed());

        TargetedMigrationProgress b2 = f.migration.migrateVersion(1, 300);
        assertEquals(300, b2.migrated());
        assertEquals(400, b2.remaining());

        TargetedMigrationProgress b3 = f.migration.migrateVersion(1, 300);
        assertEquals(300, b3.migrated());
        assertEquals(100, b3.remaining());
        assertFalse(b3.completed());

        TargetedMigrationProgress b4 = f.migration.migrateVersion(1, 300);
        assertEquals(100, b4.migrated());
        assertEquals(0, b4.remaining());
        assertTrue(b4.completed());
        assertEquals(1, b4.fromVersion());
        assertEquals(2, b4.toVersion());

        assertAllPlaintextsRecoverable(f);
        log.info("[targeted] version=1->2 op=CLEANUP basis=INTERRUPT_RESUME batches=300x3+100 result=PASS");
    }

    @Test
    void repeatedTargetedCleanupIsIdempotent() {
        Fixture f = new Fixture();
        f.km.generateAndActivate();
        seedVersion(f, 1, 50);
        f.km.rotate();

        assertTrue(f.migration.migrateVersion(1, null).completed());
        Map<String, String> cipherAfterFirst = new LinkedHashMap<>();
        f.repo.findAll().forEach(r -> cipherAfterFirst.put(r.id(), r.ciphertext()));

        // 再跑两轮：没有来源记录可处理，不迁移、不改写
        TargetedMigrationProgress again = f.migration.migrateVersion(1, null);
        TargetedMigrationProgress again2 = f.migration.migrateVersion(1, 100);
        assertEquals(0, again.migrated());
        assertEquals(0, again.remaining());
        assertTrue(again.completed());
        f.repo.findAll().forEach(r ->
                assertEquals(cipherAfterFirst.get(r.id()), r.ciphertext()));
        assertEquals(0, again2.migrated());
        assertAllPlaintextsRecoverable(f);
        log.info("[targeted] version=1->2 op=CLEANUP basis=IDEMPOTENT_REPEAT result=PASS");
    }

    @Test
    void afterMultipleRotationsEachGenerationConvergesIndependently() {
        Fixture f = new Fixture();
        f.km.generateAndActivate(); // v1
        seedVersion(f, 1, 300);
        f.km.rotate(); // v2
        seedVersion(f, 2, 300);
        f.km.rotate(); // v3 ACTIVE

        // 只清理第一代 v1，第二代 v2 必须原样保留
        TargetedMigrationProgress v1Done = f.migration.migrateVersion(1, null);
        assertTrue(v1Done.completed());
        assertEquals(0, f.refs.inspect(1).references());
        assertEquals(300, f.refs.inspect(2).references());
        long stillV2 = f.repo.findAll().stream().filter(r -> r.keyVersion() == 2).count();
        assertEquals(300, stillV2);

        // 再独立清理第二代 v2
        TargetedMigrationProgress v2Done = f.migration.migrateVersion(2, null);
        assertTrue(v2Done.completed());
        assertEquals(0, f.refs.inspect(2).references());
        f.repo.findAll().forEach(r -> assertEquals(3, r.keyVersion()));
        assertAllPlaintextsRecoverable(f);
        log.info("[targeted] version=1then2 op=CLEANUP basis=INDEPENDENT_GENERATIONS result=PASS");
    }

    @Test
    void unknownAndActiveSourceVersionsAreRejected() {
        Fixture f = new Fixture();
        f.km.generateAndActivate();
        seedVersion(f, 1, 10);
        f.km.rotate();
        assertThrows(UnknownVersionException.class, () -> f.migration.migrateVersion(99, null));
        // 当前 ACTIVE 版本不允许作为“旧版本”定向清理
        assertThrows(KeyConflictException.class, () -> f.migration.migrateVersion(2, null));
        log.warn("[targeted] version=2 op=CLEANUP basis=SOURCE_IS_ACTIVE reason=KEY_STATE_CONFLICT result=REJECTED");
    }

    @Test
    void revokedSourceFailsButPreservesOriginalCiphertext() {
        Fixture f = new Fixture();
        f.km.generateAndActivate();
        seedVersion(f, 1, 20);
        f.km.rotate();
        f.km.revoke(1); // 未清理先吊销
        TargetedMigrationProgress p = f.migration.migrateVersion(1, null);
        assertEquals(20, p.failed());
        assertEquals(0, p.migrated());
        assertEquals(20, p.remaining());
        assertFalse(p.completed());
        f.repo.findAll().forEach(r -> {
            assertEquals(1, r.keyVersion());
            assertTrue(r.ciphertext().startsWith("v1:"));
        });
        log.warn("[targeted] version=1(REVOKED)->2 op=CLEANUP basis=REVOKED_SOURCE failed=20 preserved=true result=EXPECTED_FAILURE");
    }
}
