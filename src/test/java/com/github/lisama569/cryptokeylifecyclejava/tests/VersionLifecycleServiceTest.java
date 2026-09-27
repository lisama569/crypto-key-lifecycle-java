package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionLifecycleService;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionReferenceStats;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 版本引用统计与安全下线预检：计数准确、结论可区分、随迁移实时收敛且不自相矛盾。 */
class VersionLifecycleServiceTest {

    private static final Logger log = LoggerFactory.getLogger(VersionLifecycleServiceTest.class);

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
            // 记录密文用当前 ACTIVE 加密生成后按指定版本登记，模拟该版本的历史数据
            repo.save(new DataRecord(prefix + "-" + i, km.encrypt(prefix + "-" + i),
                    version, RecordStatus.CURRENT));
        }
    }

    @Test
    void statsDistinguishActiveBlockingFromReferenceBlocking() {
        saveRecords("r", 5, 1);
        km.rotate(); // v1 RETIRED, v2 ACTIVE

        VersionReferenceStats active = lifecycle.statsFor(2);
        assertTrue(active.active());
        assertFalse(active.safeToDecommission());
        assertEquals(VersionLifecycleService.REASON_BLOCKED_ACTIVE, active.reason(),
                "current serving version must be blocked by ACTIVE, not by references");

        VersionReferenceStats retired = lifecycle.statsFor(1);
        assertFalse(retired.active());
        assertEquals(5, retired.referenceCount());
        assertFalse(retired.safeToDecommission());
        assertEquals(VersionLifecycleService.REASON_BLOCKED_BY_REFERENCES, retired.reason(),
                "retired version with references must be blocked by references");
        log.info("[references] version=1 op=REFERENCES basis=BLOCKED_BY_REFERENCES references={} result=PASS",
                retired.referenceCount());
        log.info("[references] version=2 op=REFERENCES basis=BLOCKED_ACTIVE_VERSION result=PASS");
    }

    @Test
    void statsReflectMigrationProgressInRealTimeAndConvergeToSafe() {
        saveRecords("r", 10, 1);
        km.rotate(); // v1 RETIRED with 10 references

        migration.migrateToCurrent(4);
        VersionReferenceStats mid = lifecycle.statsFor(1);
        assertEquals(6, mid.referenceCount(), "stats must reflect each committed batch");
        assertEquals(VersionLifecycleService.REASON_BLOCKED_BY_REFERENCES, mid.reason());

        migration.migrateToCurrent(4);
        assertEquals(2, lifecycle.statsFor(1).referenceCount());

        migration.migrateToCurrent(null);
        VersionReferenceStats done = lifecycle.statsFor(1);
        assertEquals(0, done.referenceCount());
        assertTrue(done.safeToDecommission());
        assertEquals(VersionLifecycleService.REASON_SAFE, done.reason());
        // 不自相矛盾：引用清零后，仓库中确实不再有任何 v1 记录
        assertEquals(0, repo.findAll().stream().filter(r -> r.keyVersion() == 1).count());
        log.info("[references] version=1 op=REFERENCES basis=CONVERGED_TO_SAFE references=0 result=PASS");
    }

    @Test
    void statsSnapshotIsInternallyConsistentAcrossVersions() {
        saveRecords("a", 3, 1);
        km.rotate(); // v1 RETIRED, v2 ACTIVE
        saveRecords("b", 2, 2);
        km.rotate(); // v2 RETIRED, v3 ACTIVE

        List<VersionReferenceStats> all = lifecycle.stats();
        assertEquals(3, all.size());
        VersionReferenceStats v1 = all.get(0);
        VersionReferenceStats v2 = all.get(1);
        VersionReferenceStats v3 = all.get(2);
        assertEquals(3, v1.referenceCount());
        assertEquals(2, v2.referenceCount());
        assertEquals(0, v3.referenceCount());
        assertTrue(v3.active());
        // 同一份快照：每个版本的计数与仓库实际分布一致
        assertEquals(v1.referenceCount(),
                repo.findAll().stream().filter(r -> r.keyVersion() == 1).count());
        assertEquals(v2.referenceCount(),
                repo.findAll().stream().filter(r -> r.keyVersion() == 2).count());
        assertEquals(VersionLifecycleService.REASON_BLOCKED_BY_REFERENCES, v1.reason());
        assertEquals(VersionLifecycleService.REASON_BLOCKED_BY_REFERENCES, v2.reason());
        assertEquals(VersionLifecycleService.REASON_BLOCKED_ACTIVE, v3.reason());
        log.info("[references] op=REFERENCES basis=SNAPSHOT_CONSISTENT versions={} result=PASS", all.size());
    }

    @Test
    void statsForUnknownVersionRejected() {
        UnknownVersionException ex = assertThrows(UnknownVersionException.class,
                () -> lifecycle.statsFor(99));
        assertEquals("UNKNOWN_VERSION", ex.reasonCode());
        log.info("[references] version=99 op=REFERENCES basis=UNKNOWN_VERSION reason=UNKNOWN_VERSION result=REJECTED");
    }

    @Test
    void revokedVersionReportsAlreadyDecommissioned() {
        km.rotate();
        km.revoke(1);
        VersionReferenceStats stats = lifecycle.statsFor(1);
        assertEquals("REVOKED", stats.state());
        assertFalse(stats.safeToDecommission());
        assertEquals(VersionLifecycleService.REASON_ALREADY_DECOMMISSIONED, stats.reason());
        log.info("[references] version=1 op=REFERENCES basis=ALREADY_DECOMMISSIONED result=PASS");
    }
}
