package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 密钥状态机：生成/启用/轮换/吊销及可区分的拒绝原因。 */
class KeyManagerTest {

    private static final Logger log = LoggerFactory.getLogger(KeyManagerTest.class);

    private KeyManager newManager() {
        return new KeyManager(new InMemoryKeyStore(), new AesGcmCipher(12, 128),
                new CipherCodec(), 256);
    }

    @Test
    void firstGenerationActivatesVersionOneAndDuplicateInitIsRejected() {
        KeyManager km = newManager();
        KeyVersion v1 = km.generateAndActivate();
        assertEquals(1, v1.version());
        assertEquals(KeyState.ACTIVE, v1.state());

        KeyConflictException ex = assertThrows(KeyConflictException.class, km::generateAndActivate);
        assertEquals("KEY_STATE_CONFLICT", ex.reasonCode());
        log.info("[lifecycle] version=1 op=GENERATE basis=FIRST_ACTIVE_THEN_DUPLICATE_REJECT reason={} result=PASS",
                ex.reasonCode());
    }

    @Test
    void rotateRetiresOldVersionAndActivatesNewVersion() {
        KeyManager km = newManager();
        KeyVersion v1 = km.generateAndActivate();
        String oldCipher = km.encrypt("before-rotation");

        KeyManager.RotationResult r = km.rotate();
        assertEquals(1, r.previousVersion());
        assertEquals(2, r.active().version());

        // 旧版本进入保留期，新版本启用；不存在两个 ACTIVE
        assertEquals(KeyState.RETIRED, km.listVersions().get(0).state());
        assertEquals(KeyState.ACTIVE, km.listVersions().get(1).state());
        assertEquals(1, km.listVersions().stream().filter(v -> v.state() == KeyState.ACTIVE).count());

        // 轮换前数据仍可由 RETIRED 版本正确解密
        assertEquals("before-rotation", km.decrypt(oldCipher));
        // 新数据只使用版本 2
        String newCipher = km.encrypt("after-rotation");
        assertEquals(2, new CipherCodec().decode(newCipher).keyVersion());
        assertEquals("after-rotation", km.decrypt(newCipher));

        log.info("[lifecycle] version={}->{} op=ROTATE basis=OLD_RETIRED_NEW_ACTIVE_OLD_DATA_DECRYPTABLE result=PASS",
                v1.version(), r.active().version());
    }

    @Test
    void rotatingMultipleTimesKeepsWholeHistoryUsableWithinRetention() {
        KeyManager km = newManager();
        km.generateAndActivate();
        String c1 = km.encrypt("v1-data");
        km.rotate();
        String c2 = km.encrypt("v2-data");
        km.rotate();
        String c3 = km.encrypt("v3-data");

        assertEquals("v1-data", km.decrypt(c1));
        assertEquals("v2-data", km.decrypt(c2));
        assertEquals("v3-data", km.decrypt(c3));
        assertEquals(3, km.currentVersion().version());
        log.info("[lifecycle] version=3 op=DECRYPT_HISTORY basis=RETIRED_IN_RETENTION result=PASS");
    }

    @Test
    void unknownVersionIsRejectedWithDistinguishableReason() {
        KeyManager km = newManager();
        km.generateAndActivate();
        // 手工构造一个版本号为 99 的合法密文信封：版本存在性校验先于解密
        String forged = km.encrypt("x").replace("v1:", "v99:");
        UnknownVersionException ex = assertThrows(UnknownVersionException.class,
                () -> km.decrypt(forged));
        assertEquals("UNKNOWN_VERSION", ex.reasonCode());
        log.warn("[lifecycle] version=99 op=DECRYPT basis=VERSION_NOT_FOUND reason={} result=REJECTED",
                ex.reasonCode());
    }

    @Test
    void revokedVersionCannotEncryptOrDecryptAndIsDistinguishable() {
        KeyManager km = newManager();
        km.generateAndActivate();
        String c1 = km.encrypt("secret-v1");
        km.rotate(); // v1 -> RETIRED, v2 ACTIVE

        km.revoke(1);
        assertEquals(KeyState.REVOKED, km.listVersions().get(0).state());

        RevokedVersionException onDecrypt = assertThrows(RevokedVersionException.class,
                () -> km.decrypt(c1));
        assertEquals("REVOKED_VERSION", onDecrypt.reasonCode());

        // 重复吊销同一版本给出同样可区分的原因
        RevokedVersionException onRevokeAgain = assertThrows(RevokedVersionException.class,
                () -> km.revoke(1));
        assertEquals("REVOKED_VERSION", onRevokeAgain.reasonCode());

        // 未知版本吊销 → UNKNOWN_VERSION，而非 REVOKED
        assertThrows(UnknownVersionException.class, () -> km.revoke(1234));

        log.warn("[lifecycle] version=1 op=REVOKE_AND_DECRYPT basis=TERMINAL_STATE reasons={}/{} result=REJECTED",
                onDecrypt.reasonCode(), onRevokeAgain.reasonCode());
    }

    @Test
    void invalidPlaintextInputIsRejectedAndServiceStaysAvailable() {
        KeyManager km = newManager();
        km.generateAndActivate();
        InvalidInputException npe = assertThrows(InvalidInputException.class,
                () -> km.encrypt(null));
        InvalidInputException empty = assertThrows(InvalidInputException.class,
                () -> km.encrypt(""));
        assertEquals("INVALID_INPUT", npe.reasonCode());
        assertEquals("INVALID_INPUT", empty.reasonCode());

        // 异常输入之后服务照常工作，且不返回错误明文
        String c = km.encrypt("still-alive");
        assertEquals("still-alive", km.decrypt(c));
        assertNotEquals("still-alive", c);
        log.info("[lifecycle] version=1 op=ENCRYPT_INVALID basis=NULL_AND_EMPTY reason={} result=REJECTED_AND_ALIVE",
                npe.reasonCode());
    }
}
