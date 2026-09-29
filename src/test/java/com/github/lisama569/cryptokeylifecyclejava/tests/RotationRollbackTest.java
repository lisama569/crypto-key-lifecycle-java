package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.RotationFailedException;
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

    /**
     * 包装内存存储：在原子切换“新→ACTIVE + 旧→RETIRED”这一步注入一次存储故障。
     * 故障点精确位于 {@link KeyStore#activateAndRetire}，是轮换期间唯一会改动
     * 在用版本状态的提交点，确定性地复现“切换提交失败”而非靠并发碰运气。
     */
    private static final class FailOnceOnRetireStore implements KeyStore {
        private final InMemoryKeyStore delegate = new InMemoryKeyStore();
        private final AtomicInteger switchCalls = new AtomicInteger();
        private volatile boolean armed = true;

        @Override public int nextVersion() { return delegate.nextVersion(); }
        @Override public void put(KeyVersion meta, SecretKey key) { delegate.put(meta, key); }
        @Override public Optional<KeyVersion> find(int version) { return delegate.find(version); }
        @Override public Optional<SecretKey> findKey(int version) { return delegate.findKey(version); }
        @Override public Optional<KeyVersion> current() { return delegate.current(); }
        @Override public List<KeyVersion> all() { return delegate.all(); }
        @Override public void updateState(KeyVersion meta) { delegate.updateState(meta); }
        @Override public void removeIfPending(int version) { delegate.removeIfPending(version); }

        @Override
        public void activateAndRetire(KeyVersion newActive, Integer retiredVersion) {
            // 第一次轮换的原子切换提交时注入存储中断
            if (armed && switchCalls.incrementAndGet() == 1) {
                throw new IllegalStateException("simulated storage outage during atomic switch");
            }
            delegate.activateAndRetire(newActive, retiredVersion);
        }

        void disarm() { armed = false; }
    }

    @Test
    void failedRotationRollsBackWithNoHalfStateAndVersionCanBeReused() {
        FailOnceOnRetireStore store = new FailOnceOnRetireStore();
        KeyManager km = new KeyManager(store, new AesGcmCipher(12, 128), new CipherCodec(), 256);
        km.generateAndActivate();
        String before = km.encrypt("survives-rotation-failure");

        // 轮换在原子切换时失败 → 可区分的 ROTATION_FAILED 原因（非通用状态冲突）
        RotationFailedException failure = assertThrows(RotationFailedException.class, km::rotate);
        assertEquals("ROTATION_FAILED", failure.reasonCode());
        assertEquals("simulated storage outage during atomic switch",
                failure.getCause().getMessage());

        // 回滚后无半更新状态：v1 恢复 ACTIVE，没有第二个版本，唯一 ACTIVE 仍是 v1
        assertEquals(1, store.all().size());
        assertEquals(KeyState.ACTIVE, store.all().get(0).state());
        assertEquals(1, km.currentVersion().version());
        // 失败期间写入的数据仍可由 v1 解密；回滚后新写入也立刻成功，不会出现没有可用版本
        assertEquals("survives-rotation-failure", km.decrypt(before));
        String afterFailure = km.encrypt("immediately-after-rollback");
        assertEquals("immediately-after-rollback", km.decrypt(afterFailure));
        assertEquals(1, new CipherCodec().decode(afterFailure).keyVersion());

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
}
