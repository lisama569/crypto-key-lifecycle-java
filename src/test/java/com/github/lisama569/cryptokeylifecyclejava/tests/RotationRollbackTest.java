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
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
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
     * 包装内存存储：第一次轮换时，在“新版本 PENDING -> ACTIVE”这一步注入一次故障。
     * 新切换顺序下旧版本尚未退役，回滚只需删除未完成的新版本，旧 ACTIVE 继续提供服务。
     */
    private static final class FailOnceOnActivateStore implements KeyStore {
        private final InMemoryKeyStore delegate = new InMemoryKeyStore();
        private final AtomicInteger updateCalls = new AtomicInteger();
        private volatile boolean armed = true;

        @Override public int nextVersion() { return delegate.nextVersion(); }
        @Override public void put(KeyVersion meta, SecretKey key) { delegate.put(meta, key); }
        @Override public Optional<KeyVersion> find(int version) { return delegate.find(version); }
        @Override public Optional<SecretKey> findKey(int version) { return delegate.findKey(version); }
        @Override public Optional<KeyVersion> current() { return delegate.current(); }
        @Override public List<KeyVersion> all() { return delegate.all(); }
        @Override public void removeUnfinishedVersion(int version) { delegate.removeUnfinishedVersion(version); }

        @Override
        public void updateState(KeyVersion meta) {
            // 第一次轮换时，在“新版本 PENDING -> ACTIVE”这一步注入故障
            if (armed && meta.state() == KeyState.ACTIVE && meta.version() == 2
                    && updateCalls.incrementAndGet() == 1) {
                throw new IllegalStateException("simulated storage outage during activation");
            }
            delegate.updateState(meta);
        }

        void disarm() { armed = false; }
    }

    @Test
    void failedRotationRollsBackWithNoHalfStateAndVersionCanBeReused() {
        FailOnceOnActivateStore store = new FailOnceOnActivateStore();
        KeyManager km = new KeyManager(store, new AesGcmCipher(12, 128), new CipherCodec(), 256);
        km.generateAndActivate();
        String before = km.encrypt("survives-rotation-failure");

        // 轮换在中途失败 → 调用方收到冲突异常
        assertThrows(KeyConflictException.class, km::rotate);

        // 回滚后无半更新状态：v1 仍 ACTIVE，没有第二个版本，唯一 ACTIVE 仍是 v1
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

        log.info("[rollback] version=1 op=ROTATE_FAILURE basis=KEEP_ACTIVE_AND_DROP_UNFINISHED result=PASS retriedTo=2");
    }
}
