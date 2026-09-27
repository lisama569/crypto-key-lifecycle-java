package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.ActiveVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionInUseException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionLifecycleService;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import com.github.lisama569.cryptokeylifecyclejava.migration.SourceCleanupProgress;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 安全下线门禁：引用清零且非当前在用版本才允许成功；各类拒绝原因可区分、状态不留半停用。 */
class DecommissionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(DecommissionServiceTest.class);

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

    private KeyState stateOf(int version) {
        return km.listVersions().stream().filter(v -> v.version() == version)
                .findFirst().orElseThrow().state();
    }

    @Test
    void decommissionActiveVersionRejectedWithDistinctReason() {
        ActiveVersionException ex = assertThrows(ActiveVersionException.class,
                () -> lifecycle.decommission(1));
        assertEquals("VERSION_IS_ACTIVE", ex.reasonCode());
        assertEquals(KeyState.ACTIVE, stateOf(1), "rejected decommission must not change state");
        // 拒绝后加解密不受影响
        String ct = km.encrypt("still-serving");
        assertEquals("still-serving", km.decrypt(ct));
        log.info("[decommission] version=1 op=DECOMMISSION basis=STILL_SERVING reason=VERSION_IS_ACTIVE result=REJECTED");
    }

    @Test
    void decommissionReferencedVersionRejectedUntilReferencesConverge() {
        saveRecords("r", 3, 1);
        km.rotate(); // v1 RETIRED with 3 references

        VersionInUseException ex = assertThrows(VersionInUseException.class,
                () -> lifecycle.decommission(1));
        assertEquals("VERSION_STILL_REFERENCED", ex.reasonCode());
        assertEquals(KeyState.RETIRED, stateOf(1), "rejected decommission must keep original state");
        // 被挡住期间旧数据仍可正常解密（没有被半停用）
        repo.findAll().forEach(r -> assertEquals("r-" + r.id().substring(2), km.decrypt(r.ciphertext())));

        // 定向清理引用收敛后，下线放行
        SourceCleanupProgress cleanup = migration.migrateFromVersion(1, null);
        assertTrue(cleanup.completed());
        KeyVersion decommissioned = lifecycle.decommission(1);
        assertEquals(KeyState.REVOKED, decommissioned.state());
        assertEquals(KeyState.REVOKED, stateOf(1));
        log.info("[decommission] version=1 op=DECOMMISSION basis=REFERENCES_ZERO result=ACCEPT");
    }

    @Test
    void decommissionUnknownVersionRejected() {
        UnknownVersionException ex = assertThrows(UnknownVersionException.class,
                () -> lifecycle.decommission(42));
        assertEquals("UNKNOWN_VERSION", ex.reasonCode());
        log.info("[decommission] version=42 op=DECOMMISSION basis=UNKNOWN_VERSION reason=UNKNOWN_VERSION result=REJECTED");
    }

    @Test
    void repeatedDecommissionGetsConsistentConflict() {
        km.rotate(); // v1 RETIRED, no references
        lifecycle.decommission(1);

        RevokedVersionException ex = assertThrows(RevokedVersionException.class,
                () -> lifecycle.decommission(1));
        assertEquals("REVOKED_VERSION", ex.reasonCode());
        assertEquals(KeyState.REVOKED, stateOf(1), "repeat submission must not alter terminal state");
        log.info("[decommission] version=1 op=DECOMMISSION basis=ALREADY_REVOKED reason=REVOKED_VERSION result=REJECTED");
    }

    @Test
    void multiGenerationCleanupThenDecommissionEachIndependently() {
        // 三代旧版本：v1/v2 RETIRED，v3 ACTIVE；v1、v2 各有数据
        saveRecords("g1", 4, 1);
        km.rotate();
        saveRecords("g2", 6, 2);
        km.rotate();
        assertEquals(KeyState.RETIRED, stateOf(1));
        assertEquals(KeyState.RETIRED, stateOf(2));
        assertEquals(KeyState.ACTIVE, stateOf(3));

        // 先清 v1 并下线 v1：v2 的引用与状态不受影响
        migration.migrateFromVersion(1, null);
        assertEquals(0, lifecycle.statsFor(1).referenceCount());
        assertEquals(6, lifecycle.statsFor(2).referenceCount());
        lifecycle.decommission(1);
        assertEquals(KeyState.REVOKED, stateOf(1));
        assertEquals(KeyState.RETIRED, stateOf(2));

        // v2 仍被引用，下线被挡；清理后才放行
        assertThrows(VersionInUseException.class, () -> lifecycle.decommission(2));
        migration.migrateFromVersion(2, null);
        lifecycle.decommission(2);
        assertEquals(KeyState.REVOKED, stateOf(2));

        // 当前 ACTIVE 永远被挡
        KeyLifecycleException active = assertThrows(ActiveVersionException.class,
                () -> lifecycle.decommission(3));
        assertEquals("VERSION_IS_ACTIVE", active.reasonCode());
        assertEquals(KeyState.ACTIVE, stateOf(3));

        // 全部历史数据明文含义不变
        repo.findAll().forEach(r -> {
            String expected = r.id().startsWith("g1") ? "g1-" + r.id().substring(3)
                    : "g2-" + r.id().substring(3);
            assertEquals(expected, km.decrypt(r.ciphertext()));
            assertEquals(3, r.keyVersion(), "all records converged to active version");
        });
        log.info("[decommission] op=DECOMMISSION basis=MULTI_GENERATION_INDEPENDENT generations=2 result=PASS");
    }
}
