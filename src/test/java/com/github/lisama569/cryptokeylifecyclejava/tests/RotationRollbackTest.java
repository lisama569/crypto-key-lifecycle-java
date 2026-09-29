package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.RotationRecoveryException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 轮换在“旧版本已转 RETIRED”之后失败时，必须完整回滚且可立即重试。 */
class RotationRollbackTest {

    private static final Logger log = LoggerFactory.getLogger(RotationRollbackTest.class);

    /** 包装内存存储：当 PENDING 种子已写入、且调用次数达到阈值时，让旧版本状态更新失败一次。 */
    private static final class FailOnceOnRetireStore implements KeyStore {
        private final InMemoryKeyStore delegate = new InMemoryKeyStore();
        private final AtomicInteger updateCalls = new AtomicInteger();
        private volatile boolean armed = true;

        @Override public int nextVersion() { return delegate.nextVersion(); }
        @Override public void put(KeyVersion meta, SecretKey key) { delegate.put(meta, key); }
        @Override public Optional<KeyVersion> find(int version) { return delegate.find(version); }
        @Override public Optional<SecretKey> findKey(int version) { return delegate.findKey(version); }
        @Override public Optional<KeyVersion> current() { return delegate.current(); }
        @Override public List<KeyVersion> all() { return delegate.all(); }
        @Override public void removeIfPending(int version) { delegate.removeIfPending(version); }

        @Override
        public void updateState(KeyVersion meta) {
            // 第一次轮换时，在“旧 ACTIVE -> RETIRED”这一步注入故障
            if (armed && meta.state() == KeyState.RETIRED
                    && updateCalls.incrementAndGet() == 1) {
                throw new IllegalStateException("simulated storage outage during retire");
            }
            delegate.updateState(meta);
        }

        void disarm() { armed = false; }
    }

    @Test
    void failedRotationRollsBackWithNoHalfStateAndVersionCanBeReused() {
        FailOnceOnRetireStore store = new FailOnceOnRetireStore();
        KeyManager km = new KeyManager(store, new AesGcmCipher(12, 128), new CipherCodec(), 256);
        km.generateAndActivate();
        String before = km.encrypt("survives-rotation-failure");

        // 轮换在中途失败 → 调用方收到冲突异常
        assertThrows(KeyConflictException.class, km::rotate);

        // 回滚后无半更新状态：v1 恢复 ACTIVE，没有第二个版本，唯一 ACTIVE 仍是 v1
        assertEquals(1, store.all().size());
        assertEquals(KeyState.ACTIVE, store.all().get(0).state());
        assertEquals(1, km.currentVersion().version());
        // 失败期间写入的数据仍可由 v1 解密
        assertEquals("survives-rotation-failure", km.decrypt(before));

        // 故障解除后立即重试：复用版本号 2，干净地完成轮换
        store.disarm();
        KeyManager.RotationResult result = km.rotate();
        assertEquals(1, result.previousVersion());
        assertEquals(2, result.active().version());
        assertEquals(2, store.all().size());
        assertEquals(KeyState.RETIRED, store.all().get(0).state());
        assertEquals(KeyState.ACTIVE, store.all().get(1).state());
        assertEquals("survives-rotation-failure", km.decrypt(before));
        assertEquals(2, km.encrypt("after-retry").startsWith("v2:") ? 2 : -1);

        log.info("[rollback] version=1 op=ROTATE_FAILURE basis=RESTORE_ACTIVE_AND_DROP_PENDING result=PASS retriedTo=2");
    }

    /** 在最后一步“新版本 PENDING -> ACTIVE”注入故障：旧版本此前已被转 RETIRED。 */
    private static final class FailOnceOnActivateStore implements KeyStore {
        private final InMemoryKeyStore delegate = new InMemoryKeyStore();
        private volatile boolean armed = true;

        @Override public int nextVersion() { return delegate.nextVersion(); }
        @Override public void put(KeyVersion meta, SecretKey key) { delegate.put(meta, key); }
        @Override public Optional<KeyVersion> find(int version) { return delegate.find(version); }
        @Override public Optional<SecretKey> findKey(int version) { return delegate.findKey(version); }
        @Override public Optional<KeyVersion> current() { return delegate.current(); }
        @Override public List<KeyVersion> all() { return delegate.all(); }
        @Override public void removeIfPending(int version) { delegate.removeIfPending(version); }

        @Override
        public void updateState(KeyVersion meta) {
            if (armed && meta.state() == KeyState.ACTIVE && meta.version() != 1) {
                armed = false;
                throw new IllegalStateException("simulated storage outage during activation");
            }
            delegate.updateState(meta);
        }

        void disarm() { armed = false; }
    }

    @Test
    void failureAtFinalActivationStillRollsBackToSingleUsableActive() {
        FailOnceOnActivateStore store = new FailOnceOnActivateStore();
        KeyManager km = new KeyManager(store, new AesGcmCipher(12, 128), new CipherCodec(), 256);
        km.generateAndActivate();
        String before = km.encrypt("old-data");

        assertThrows(KeyConflictException.class, km::rotate);

        // 回滚后：v1 恢复 ACTIVE，PENDING 新种子被清除，仍有恰好一个可用版本，无半更新
        assertEquals(1, store.all().size());
        assertEquals(KeyState.ACTIVE, store.all().get(0).state());
        assertEquals(1, km.currentVersion().version());
        assertEquals("old-data", km.decrypt(before));

        // 解除故障后重试成功，复用版本号 2
        store.disarm();
        assertEquals(2, km.rotate().active().version());
        assertEquals("old-data", km.decrypt(before));
        assertEquals(2, new CipherCodec().decode(km.encrypt("new-data")).keyVersion());
        log.info("[rollback] version=1 op=ROTATE_FAILURE_AT_ACTIVATE basis=RESTORE_ACTIVE result=PASS");
    }

    /**
     * 回滚动作本身也故障：恢复旧版本 ACTIVE 时再次抛错。此时必须抛出与普通冲突
     * 可区分的 {@link RotationRecoveryException}，且系统中仍应能找到需要人工关注的线索。
     */
    private static final class RollbackAlsoFailsStore implements KeyStore {
        private final InMemoryKeyStore delegate = new InMemoryKeyStore();
        private volatile boolean retireFailedOnce = false;

        @Override public int nextVersion() { return delegate.nextVersion(); }
        @Override public void put(KeyVersion meta, SecretKey key) { delegate.put(meta, key); }
        @Override public Optional<KeyVersion> find(int version) { return delegate.find(version); }
        @Override public Optional<SecretKey> findKey(int version) { return delegate.findKey(version); }
        @Override public Optional<KeyVersion> current() { return delegate.current(); }
        @Override public List<KeyVersion> all() { return delegate.all(); }
        @Override
        public void removeIfPending(int version) { delegate.removeIfPending(version); }

        @Override
        public void updateState(KeyVersion meta) {
            // 第一次：让“旧 ACTIVE -> RETIRED”成功落库后，后续“新版本 -> ACTIVE”失败触发回滚
            if (meta.state() == KeyState.RETIRED) {
                delegate.updateState(meta);
                retireFailedOnce = true;
                return;
            }
            if (retireFailedOnce && meta.state() == KeyState.ACTIVE && meta.version() == 2) {
                throw new IllegalStateException("activation outage");
            }
            // 回滚会尝试把 v1 恢复 ACTIVE：让它也失败，制造“回滚本身失败”
            if (retireFailedOnce && meta.state() == KeyState.ACTIVE && meta.version() == 1
                    && delegate.find(1).map(m -> m.state() == KeyState.RETIRED).orElse(false)) {
                retireFailedOnce = false;
                throw new IllegalStateException("rollback outage");
            }
            delegate.updateState(meta);
        }
    }

    @Test
    void failureDuringRollbackRaisesDistinguishableRecoveryError() {
        RollbackAlsoFailsStore store = new RollbackAlsoFailsStore();
        KeyManager km = new KeyManager(store, new AesGcmCipher(12, 128), new CipherCodec(), 256);
        km.generateAndActivate();

        RotationRecoveryException ex = assertThrows(RotationRecoveryException.class, km::rotate);
        assertEquals("ROTATION_RECOVERY_FAILED", ex.reasonCode());
        // 原因链里带得动底层故障，便于排查
        assertTrue(ex.getMessage().contains("unsafe state"), ex.getMessage());
        assertTrue(ex.getCause() instanceof IllegalStateException, "underlying cause must be preserved");
        // 与普通“轮换失败但已干净回滚”的 KEY_STATE_CONFLICT 严格可区分
        assertTrue(!ex.reasonCode().equals("KEY_STATE_CONFLICT"));
        log.error("[rollback] version=1 op=ROTATE_ROLLBACK_FAILURE reason={} result=REJECTED", ex.reasonCode());
    }
}
