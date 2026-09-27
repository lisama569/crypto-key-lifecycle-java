package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.decommission.MaintenanceLock;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceReport;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceService;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 版本引用统计与安全下线预检：实时计数、阻塞原因区分、迁移过程中引用收敛。 */
class VersionReferenceServiceTest {

    private static final Logger log = LoggerFactory.getLogger(VersionReferenceServiceTest.class);

    private static final class Fixture {
        final KeyManager km = new KeyManager(new InMemoryKeyStore(),
                new AesGcmCipher(12, 128), new CipherCodec(), 256);
        final InMemoryDataRepository repo = new InMemoryDataRepository();
        final MaintenanceLock lock = new MaintenanceLock();
        MigrationService migration;
        VersionReferenceService refs;

        Fixture wire() {
            migration = new MigrationService(km, repo, lock);
            refs = new VersionReferenceService(km, repo, lock);
            return this;
        }
    }

    private Fixture seed(int v1Count, int v2Count, int v3Count) {
        Fixture f = new Fixture().wire();
        f.km.generateAndActivate(); // v1
        for (int i = 0; i < v1Count; i++) {
            f.repo.save(new DataRecord("v1-" + i, f.km.encrypt("v1#" + i), 1, RecordStatus.CURRENT));
        }
        f.km.rotate(); // v2
        for (int i = 0; i < v2Count; i++) {
            f.repo.save(new DataRecord("v2-" + i, f.km.encrypt("v2#" + i), 2, RecordStatus.CURRENT));
        }
        f.km.rotate(); // v3
        for (int i = 0; i < v3Count; i++) {
            f.repo.save(new DataRecord("v3-" + i, f.km.encrypt("v3#" + i), 3, RecordStatus.CURRENT));
        }
        return f;
    }

    @Test
    void referencesCountedPerVersionAndActiveVersionIsBlocked() {
        Fixture f = seed(1200, 0, 500);

        VersionReferenceReport v1 = f.refs.inspect(1);
        assertEquals(1200, v1.references());
        assertEquals("RETIRED", v1.state());
        assertFalse(v1.canDecommission());
        assertEquals("STILL_REFERENCED", v1.blockedReason());
        assertEquals(3, v1.activeVersion());

        // 当前服务版本：阻塞原因必须与“被数据引用”区分开
        VersionReferenceReport v3 = f.refs.inspect(3);
        assertEquals(500, v3.references());
        assertFalse(v3.canDecommission());
        assertEquals("CURRENTLY_ACTIVE", v3.blockedReason());

        // 没有任何数据的 v2 仍然 RETIRED 但引用为 0：可安全下线
        VersionReferenceReport v2 = f.refs.inspect(2);
        assertEquals(0, v2.references());
        assertTrue(v2.canDecommission());
        assertNull(v2.blockedReason());
        log.info("[refs] version=1 op=INSPECT basis=STILL_REFERENCED references=1200 result=PASS");
    }

    @Test
    void unknownVersionInspectionIsRejected() {
        Fixture f = seed(0, 0, 0);
        UnknownVersionException ex = assertThrows(UnknownVersionException.class,
                () -> f.refs.inspect(42));
        assertEquals("UNKNOWN_VERSION", ex.reasonCode());
        log.warn("[refs] version=42 op=INSPECT basis=UNKNOWN_VERSION reason=UNKNOWN_VERSION result=REJECTED");
    }

    @Test
    void referencesConvergeInRealTimeAsTargetedCleanupProceeds() {
        Fixture f = seed(1000, 0, 10);
        // 分批清理 v1，每批之间引用统计必须单调下降且与实际数据一致
        int[] expected = {700, 400, 100, 0};
        for (int i = 0; i < expected.length; i++) {
            f.migration.migrateVersion(1, 300);
            VersionReferenceReport report = f.refs.inspect(1);
            long actual = f.repo.findAll().stream().filter(r -> r.keyVersion() == 1).count();
            assertEquals(expected[i], report.references(), "report must match actual data at step " + i);
            assertEquals(actual, report.references(), "report must not contradict stored data");
        }
        VersionReferenceReport done = f.refs.inspect(1);
        assertTrue(done.canDecommission());
        assertNull(done.blockedReason());

        // 引用清零时所有历史数据仍能用当前版本解开——统计与可解密性不自相矛盾
        f.repo.findAll().forEach(r -> {
            String plain = f.km.decrypt(r.ciphertext());
            assertTrue(plain.startsWith("v1#") || plain.startsWith("v3#"));
        });
        log.info("[refs] version=1 op=INSPECT_AFTER_CLEANUP basis=REFERENCES_ZERO references=0 canDecommission=true result=PASS");
    }

    @Test
    void revokedAndDecommissionedStatesHaveDistinctBlockReasons() {
        Fixture f = seed(1, 0, 0);
        f.km.revoke(1);
        VersionReferenceReport revoked = f.refs.inspect(1);
        assertFalse(revoked.canDecommission());
        assertEquals("ALREADY_REVOKED", revoked.blockedReason());
        log.info("[refs] version=1 op=INSPECT basis=ALREADY_REVOKED result=PASS");
    }
}
