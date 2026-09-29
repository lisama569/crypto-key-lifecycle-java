package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 确定性覆盖“轮换进行中在线写入不允许失败”的时序：
 * 用可在轮换中间步骤精确挂起的存储包装，钉住“旧版本已 RETIRED、新版本未 ACTIVE”的窗口。
 */
class RotationConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(RotationConcurrencyTest.class);

    private KeyManager newManager(KeyStore store) {
        return new KeyManager(store, new AesGcmCipher(12, 128), new CipherCodec(), 256);
    }

    /**
     * 在“旧 ACTIVE -&gt; RETIRED 已落库、新版本尚未 ACTIVE”这一步阻塞轮换线程，
     * 直到测试显式放行（reached 通知测试已到窗口；release 放行）。
     */
    static final class MidRotationParkingStore implements KeyStore {
        private final InMemoryKeyStore delegate = new InMemoryKeyStore();
        final CountDownLatch reached = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);
        volatile boolean armed = true;

        @Override public int nextVersion() { return delegate.nextVersion(); }
        @Override public void put(KeyVersion meta, SecretKey key) { delegate.put(meta, key); }
        @Override public Optional<KeyVersion> find(int version) { return delegate.find(version); }
        @Override public Optional<SecretKey> findKey(int version) { return delegate.findKey(version); }
        @Override public Optional<KeyVersion> current() { return delegate.current(); }
        @Override public List<KeyVersion> all() { return delegate.all(); }
        @Override public void removeIfPending(int version) { delegate.removeIfPending(version); }

        @Override
        public void updateState(KeyVersion meta) {
            // 先让“旧 ACTIVE -> RETIRED”真正落库，再停在“新版本仍 PENDING”的空窗点上
            delegate.updateState(meta);
            if (armed && meta.state() == KeyState.RETIRED) {
                reached.countDown();
                try {
                    assertTrue(release.await(30, TimeUnit.SECONDS), "test must release the parked rotation");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
            }
        }
    }

    @Test
    void encryptionHasNoNoActiveVersionWindowDuringRotation() throws Exception {
        MidRotationParkingStore store = new MidRotationParkingStore();
        KeyManager km = newManager(store);
        km.generateAndActivate();
        String oldCipher = km.encrypt("written-before-rotation");

        ExecutorService pool = Executors.newCachedThreadPool();
        try {
            // 启动轮换，并等待它精确停在“旧版本已 RETIRED、新版本仍 PENDING”的窗口
            Future<KeyManager.RotationResult> rotation = pool.submit(km::rotate);
            assertTrue(store.reached.await(5, TimeUnit.SECONDS), "rotation should reach the mid-point");

            // 此刻并发写入：正确行为是等待轮换完成后成功，而不是立即抛“no active key version”。
            // 旧实现在这里会立刻以 KEY_STATE_CONFLICT 失败；修复后调用被阻塞，250ms 内不会返回。
            Future<String> duringWrite = pool.submit(() -> km.encrypt("written-during-rotation"));
            assertThrows(TimeoutException.class, () -> duringWrite.get(250, TimeUnit.MILLISECONDS),
                    "encrypt must block while the rotation mid-state is private, not fail fast");
            assertFalse(duringWrite.isDone(), "no encryption failure may surface during the rotation window");

            // 轮换前的历史数据：旧版本此刻处于 RETIRED，解密必须照常立即成功，
            // 既不能报“没有可用版本”，也不能因为轮换而失败
            Future<String> oldRead = pool.submit(() -> km.decrypt(oldCipher));
            assertEquals("written-before-rotation", oldRead.get(5, TimeUnit.SECONDS));

            // 放行轮换，原子切换完成
            store.release.countDown();
            KeyManager.RotationResult result = rotation.get(5, TimeUnit.SECONDS);
            assertEquals(1, result.previousVersion());
            assertEquals(2, result.active().version());

            // 被阻塞的写入在切换完成后成功，使用的是新版本，且能正确解开
            String duringCipher = duringWrite.get(5, TimeUnit.SECONDS);
            assertEquals(2, new CipherCodec().decode(duringCipher).keyVersion());
            assertEquals("written-during-rotation", km.decrypt(duringCipher));

            // 轮换前的历史数据仍可由旧版本解开（再验一次）
            assertEquals("written-before-rotation", km.decrypt(oldCipher));

            // 全程没有出现过“两个 ACTIVE”，终态恰好一个在用版本
            assertEquals(1, km.listVersions().stream().filter(v -> v.state() == KeyState.ACTIVE).count());
            assertEquals(2, km.currentVersion().version());
            assertEquals(KeyState.RETIRED, km.listVersions().get(0).state());
            assertEquals(KeyState.ACTIVE, km.listVersions().get(1).state());
            log.info("[rotation-window] op=ROTATE_VS_ENCRYPT basis=SWITCH_ATOMIC_VISIBLE result=PASS");
        } finally {
            store.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void repeatedRotationsInterleavedWithWritersNeverLoseAnActiveVersion() throws Exception {
        MidRotationParkingStore store = new MidRotationParkingStore();
        KeyManager km = newManager(store);
        km.generateAndActivate();

        int writers = 8;
        int rotations = 5;
        int perWriter = 300;
        ExecutorService pool = Executors.newCachedThreadPool();
        CountDownLatch start = new CountDownLatch(1);
        java.util.concurrent.ConcurrentHashMap<String, String> produced = new java.util.concurrent.ConcurrentHashMap<>();
        AtomicInteger failures = new AtomicInteger();
        try {
            // 第一轮轮换故意停在中间窗口，此时所有写入线程已经在跑；放行后再交错执行其余轮换
            Future<KeyManager.RotationResult> firstRotation = pool.submit(km::rotate);
            assertTrue(store.reached.await(5, TimeUnit.SECONDS));

            List<Future<?>> writerFutures = new java.util.ArrayList<>();
            for (int w = 0; w < writers; w++) {
                final int workerId = w;
                writerFutures.add(pool.submit(() -> {
                    start.await();
                    for (int i = 0; i < perWriter; i++) {
                        try {
                            String plain = "w" + workerId + "-m" + i;
                            produced.put(km.encrypt(plain), plain);
                        } catch (RuntimeException ex) {
                            failures.incrementAndGet();
                        }
                    }
                    return null;
                }));
            }
            start.countDown(); // 写入线程开始抢锁并在轮换窗口上排队

            // 给写入线程时间在写锁上排队，然后放行使第一轮切换完成
            Thread.sleep(200);
            store.release.countDown();
            assertEquals(2, firstRotation.get(5, TimeUnit.SECONDS).active().version());

            // 后续轮换与持续写入继续交错
            List<Future<?>> rotationFutures = new java.util.ArrayList<>();
            for (int r = 1; r < rotations; r++) {
                rotationFutures.add(pool.submit(km::rotate));
            }
            for (Future<?> f : writerFutures) {
                f.get(30, TimeUnit.SECONDS);
            }
            for (Future<?> f : rotationFutures) {
                f.get(30, TimeUnit.SECONDS);
            }

            assertEquals(0, failures.get(), "no write may fail because of a rotation");
            assertEquals(writers * perWriter, produced.size());

            // 每条密文都能按其信封版本正确解开，且版本只可能是曾经的 ACTIVE
            CipherCodec codec = new CipherCodec();
            produced.forEach((cipher, expectedPlain) -> {
                int v = codec.decode(cipher).keyVersion();
                assertEquals(expectedPlain, km.decrypt(cipher));
                KeyState st = km.listVersions().get(v - 1).state();
                assertTrue(st == KeyState.ACTIVE || st == KeyState.RETIRED,
                        "data must never be sealed under " + st);
            });

            // 最终恰好一个在用版本，且没有重复启用过同一版本号
            assertEquals(1 + rotations, km.currentVersion().version());
            assertEquals(1, km.listVersions().stream().filter(v -> v.state() == KeyState.ACTIVE).count());
            assertEquals(1 + rotations, km.listVersions().size());
            log.info("[rotation-window] op=ROTATE_VS_ENCRYPT_STRESS messages={} finalVersion={} basis=NEVER_NO_ACTIVE result=PASS",
                    produced.size(), km.currentVersion().version());
        } finally {
            store.release.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void noActiveVersionErrorIsStillReturnedWhenStoreIsCompletelyEmpty() {
        // 防御性：在从未初始化的空系统上加密，仍应得到可区分的 KEY_STATE_CONFLICT
        KeyManager km = newManager(new InMemoryKeyStore());
        KeyConflictException ex = assertThrows(KeyConflictException.class,
                () -> km.encrypt("nothing-to-use"));
        assertEquals("KEY_STATE_CONFLICT", ex.reasonCode());
    }
}
