package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.decommission.MaintenanceLock;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionDecommissionService;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceReport;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceService;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionActiveException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionDecommissionedException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionStillReferencedException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 安全下线门禁：可下线闭环、各类拒绝原因可区分、终态后加解密状态正确。 */
class VersionDecommissionServiceTest {

    private static final Logger log = LoggerFactory.getLogger(VersionDecommissionServiceTest.class);

    private static final class Fixture {
        final KeyManager km = new KeyManager(new InMemoryKeyStore(),
                new AesGcmCipher(12, 128), new CipherCodec(), 256);
        final InMemoryDataRepository repo = new InMemoryDataRepository();
        final MaintenanceLock lock = new MaintenanceLock();
        MigrationService migration;
        VersionReferenceService refs;
        VersionDecommissionService decom;

        Fixture wire() {
            migration = new MigrationService(km, repo, lock);
            refs = new VersionReferenceService(km, repo, lock);
            decom = new VersionDecommissionService(km, repo, lock, refs);
            return this;
        }
    }

    @Test
    void fullSafeDecommissionLifecycleSucceedsOnlyAfterReferencesCleared() {
        Fixture f = new Fixture().wire();
        f.km.generateAndActivate(); // v1
        for (int i = 0; i < 500; i++) {
            f.repo.save(new DataRecord("r" + i, f.km.encrypt("m#" + i), 1, RecordStatus.CURRENT));
        }
        f.km.rotate(); // v2 ACTIVE, v1 RETIRED

        // 预检：被引用挡住
        VersionReferenceReport pre = f.decom.preflight(1);
        assertFalse(pre.canDecommission());
        assertEquals("STILL_REFERENCED", pre.blockedReason());

        // 直接下线被拒绝，版本保持 RETIRED，数据仍可解
        VersionStillReferencedException blocked = assertThrows(VersionStillReferencedException.class,
                () -> f.decom.decommission(1));
        assertEquals("VERSION_STILL_REFERENCED", blocked.reasonCode());
        assertEquals(KeyState.RETIRED, f.km.getVersion(1).state());
        String oldV1Cipher = f.repo.findById("r0").orElseThrow().ciphertext();
        assertEquals("m#0", f.km.decrypt(oldV1Cipher));

        // 清理后引用归零，下线成功
        assertTrue(f.migration.migrateVersion(1, null).completed());
        assertEquals(KeyState.DECOMMISSIONED, f.decom.decommission(1).state());

        // 终态：迁移前残留的 v1 密文再解密被明确拒绝；已迁移到 v2 的在库数据正常可解
        VersionDecommissionedException decryptRejected = assertThrows(VersionDecommissionedException.class,
                () -> f.km.decrypt(oldV1Cipher));
        assertEquals("VERSION_DECOMMISSIONED", decryptRejected.reasonCode());
        assertEquals("m#0", f.km.decrypt(f.repo.findById("r0").orElseThrow().ciphertext()));
        String fresh = f.km.encrypt("fresh");
        assertEquals("fresh", f.km.decrypt(fresh));
        log.info("[decommission] version=1 op=DECOMMISSION basis=CLEANUP_THEN_GATE state=DECOMMISSIONED result=PASS");
    }

    @Test
    void servingVersionCannotBeDecommissioned() {
        Fixture f = new Fixture().wire();
        f.km.generateAndActivate();
        VersionActiveException ex = assertThrows(VersionActiveException.class,
                () -> f.decom.decommission(1));
        assertEquals("VERSION_ACTIVE", ex.reasonCode());
        assertEquals(KeyState.ACTIVE, f.km.getVersion(1).state());
        log.warn("[decommission] version=1 op=DECOMMISSION basis=CURRENTLY_ACTIVE reason=VERSION_ACTIVE result=REJECTED");
    }

    @Test
    void unknownAndRevokedVersionsAreRejectedWithDistinctReasons() {
        Fixture f = new Fixture().wire();
        f.km.generateAndActivate();
        f.km.rotate(); // v2 active, v1 retired
        assertThrows(UnknownVersionException.class, () -> f.decom.decommission(99));
        f.km.revoke(1);
        KeyLifecycleException revoked = assertThrows(RevokedVersionException.class,
                () -> f.decom.decommission(1));
        assertEquals("REVOKED_VERSION", revoked.reasonCode());
        log.warn("[decommission] version=1 op=DECOMMISSION basis=ALREADY_REVOKED reason=REVOKED_VERSION result=REJECTED");
    }

    @Test
    void repeatedDecommissionAfterSuccessIsStableConflict() {
        Fixture f = new Fixture().wire();
        f.km.generateAndActivate();
        f.km.rotate(); // v2 active, v1 retired 且无数据引用
        assertEquals(KeyState.DECOMMISSIONED, f.decom.decommission(1).state());
        VersionDecommissionedException again = assertThrows(VersionDecommissionedException.class,
                () -> f.decom.decommission(1));
        assertEquals("VERSION_DECOMMISSIONED", again.reasonCode());
        // 第三次预检仍给出一致结论
        assertEquals("ALREADY_DECOMMISSIONED", f.decom.preflight(1).blockedReason());
        log.warn("[decommission] version=1 op=DECOMMISSION basis=ALREADY_DECOMMISSIONED reason=VERSION_DECOMMISSIONED result=REJECTED");
    }
}
