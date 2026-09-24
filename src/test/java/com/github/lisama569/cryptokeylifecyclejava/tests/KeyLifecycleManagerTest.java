package com.github.lisama569.cryptokeylifecyclejava.tests;

import com.github.lisama569.cryptokeylifecyclejava.audit.AuditLogger;
import com.github.lisama569.cryptokeylifecyclejava.config.KeyLifecycleProperties;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.FailureReason;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyLifecycleManager;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecordStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 生命周期状态机单测：生成/启用/轮换/吊销的合法与非法转换，
 * 以及 UNKNOWN_VERSION / REVOKED_VERSION / INVALID_VERSION_STATE 三类原因可区分。
 */
class KeyLifecycleManagerTest {

    private static final Logger testLog = LoggerFactory.getLogger("KEY_LIFECYCLE_TEST");

    private KeyLifecycleManager manager;

    @BeforeEach
    void setUp() {
        manager = new KeyLifecycleManager(new AuditLogger(), new EncryptedRecordStore(),
                new KeyLifecycleProperties());
    }

    @Test
    @DisplayName("生成 → 启用：新版本 ENABLED")
    void generateAndEnable() {
        KeyVersion v = manager.generateKey();
        assertEquals(KeyState.CREATED, v.getState());
        KeyVersion enabled = manager.enableVersion(v.getVersion());
        assertEquals(KeyState.ENABLED, enabled.getState());
        assertEquals(v.getVersion(), manager.currentVersion().getVersion());
        testLog.info("op=ENABLE keyVersion={} decision=ALLOWED reason='created->enabled'", v.getVersion());
    }

    @Test
    @DisplayName("重复启用同一版本 → INVALID_VERSION_STATE，不改变当前版本")
    void duplicateEnableRejected() {
        KeyVersion v = manager.enableVersion(manager.generateKey().getVersion());
        KeyLifecycleException ex = assertThrows(KeyLifecycleException.class,
                () -> manager.enableVersion(v.getVersion()));
        assertEquals(FailureReason.INVALID_VERSION_STATE, ex.getReason());
        assertEquals(v.getVersion(), manager.currentVersion().getVersion());
        testLog.info("op=ENABLE keyVersion={} decision=REJECTED reason='{}'", v.getVersion(), ex.getReason());
    }

    @Test
    @DisplayName("轮换：旧版本 RETIRED 且仍可解密；新版本成为当前；不能重复启用旧版本")
    void rotateRetiresOldVersion() {
        int first = manager.rotate().getVersion(); // 无初始版本时第一次轮换
        int second = manager.rotate().getVersion();
        assertEquals(second, manager.currentVersion().getVersion());
        assertEquals(KeyState.RETIRED, manager.requireVersion(first).getState());
        // 保留期内解密路由必须放行 RETIRED
        assertEquals(KeyState.RETIRED, manager.requireVersionForDecrypt(first).getState());

        KeyLifecycleException ex = assertThrows(KeyLifecycleException.class,
                () -> manager.enableVersion(first));
        assertEquals(FailureReason.INVALID_VERSION_STATE, ex.getReason());
        testLog.info("op=ROTATE keyVersion={} decision=ALLOWED reason='old {} retired but decryptable'",
                second, first);
    }

    @Test
    @DisplayName("未知版本：启用/吊销/解密路由分别得到 UNKNOWN_VERSION")
    void unknownVersionRejected() {
        KeyLifecycleException e1 = assertThrows(KeyLifecycleException.class,
                () -> manager.enableVersion(999));
        KeyLifecycleException e2 = assertThrows(KeyLifecycleException.class,
                () -> manager.revokeVersion(999));
        KeyLifecycleException e3 = assertThrows(KeyLifecycleException.class,
                () -> manager.requireVersionForDecrypt(999));
        assertEquals(FailureReason.UNKNOWN_VERSION, e1.getReason());
        assertEquals(FailureReason.UNKNOWN_VERSION, e2.getReason());
        assertEquals(FailureReason.UNKNOWN_VERSION, e3.getReason());
        testLog.info("op=* keyVersion=999 decision=REJECTED reason='UNKNOWN_VERSION'");
    }

    @Test
    @DisplayName("无引用 RETIRED 版本可吊销；吊销后任何使用得到 REVOKED_VERSION")
    void revokeRetiredVersion() {
        int first = manager.rotate().getVersion();
        int second = manager.rotate().getVersion();
        manager.revokeVersion(first);
        assertEquals(KeyState.REVOKED, manager.requireVersion(first).getState());

        KeyLifecycleException decryptEx = assertThrows(KeyLifecycleException.class,
                () -> manager.requireVersionForDecrypt(first));
        assertEquals(FailureReason.REVOKED_VERSION, decryptEx.getReason());
        KeyLifecycleException enableEx = assertThrows(KeyLifecycleException.class,
                () -> manager.enableVersion(first));
        assertEquals(FailureReason.REVOKED_VERSION, enableEx.getReason());
        // 重复吊销也是 REVOKED_VERSION
        KeyLifecycleException doubleRevoke = assertThrows(KeyLifecycleException.class,
                () -> manager.revokeVersion(first));
        assertEquals(FailureReason.REVOKED_VERSION, doubleRevoke.getReason());
        testLog.info("op=REVOKE keyVersion={} decision=ALLOWED reason='retired with no references'; current={}",
                first, second);
    }

    @Test
    @DisplayName("当前 ENABLED 版本禁止直接吊销 → INVALID_VERSION_STATE")
    void cannotRevokeCurrentEnabled() {
        int current = manager.rotate().getVersion();
        KeyLifecycleException ex = assertThrows(KeyLifecycleException.class,
                () -> manager.revokeVersion(current));
        assertEquals(FailureReason.INVALID_VERSION_STATE, ex.getReason());
        assertEquals(KeyState.ENABLED, manager.requireVersion(current).getState());
        testLog.info("op=REVOKE keyVersion={} decision=REJECTED reason='{}'", current, ex.getReason());
    }

    @Test
    @DisplayName("启动引导（反射触发 @PostConstruct）：默认配置自动启用 v1")
    void bootstrapEnablesInitialVersion() throws Exception {
        KeyLifecycleManager fresh = new KeyLifecycleManager(new AuditLogger(),
                new EncryptedRecordStore(), new KeyLifecycleProperties());
        Method bootstrap = KeyLifecycleManager.class.getDeclaredMethod("bootstrap");
        bootstrap.setAccessible(true);
        bootstrap.invoke(fresh);
        assertEquals(1, fresh.currentVersion().getVersion());
        assertEquals(KeyState.ENABLED, fresh.currentVersion().getState());
        testLog.info("op=ENABLE keyVersion=1 decision=ALLOWED reason='@PostConstruct bootstrap'");
    }
}
