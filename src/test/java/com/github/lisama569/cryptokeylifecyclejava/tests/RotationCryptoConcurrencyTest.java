package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.RotationFailedException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 确定性覆盖“轮换 × 在线加解密”的并发时序，不依赖线程调度碰运气。
 *
 * <p>存储在原子切换的两次状态写入之间（仍持有存储 monitor）暴露一个栅栏：
 * 轮换线程被精确挂在临界瞬间（旧版本已 RETIRED、新版本尚未 ACTIVE）时，让大量
 * 加密线程一起冲进 {@code current()}。
 * <ul>
 *   <li>错误实现（两次写入跨两个临界区、或读路径不同步）：挂起点存在零个 ACTIVE，
 *       加密线程会确定性拿到“没有可用密钥版本”，本用例必挂；</li>
 *   <li>本实现（同一次 monitor 临界区提交，失败当场自愈，读路径同 monitor）：
 *       挂起点读者全部排队在 monitor 上，释放后看到的都是完整的切换后状态，
 *       加密无一失败。</li>
 * </ul>
 * 同一栅栏还注入“提交中途存储故障”，确定性覆盖失败回滚与在线加密的交错。
 */
class RotationCryptoConcurrencyTest {

    private static final Logger log =
            LoggerFactory.getLogger(RotationCryptoConcurrencyTest.class);

    /** 在原子切换两次写入之间可挂起/可注入故障的存储（直接使用生产实现的同步路径）。 */
    private static final class ProbeStore extends InMemoryKeyStore {
        /** 轮换线程进入两次写入之间的临界瞬间。 */
        final CountDownLatch reachedMidSwitch = new CountDownLatch(1);
        /** 释放后轮换线程才完成第二次写入。 */
        volatile CountDownLatch release = new CountDownLatch(1);
        /** true 时在栅栏点抛出存储故障，新版本的 ACTIVE 写入不发生。 */
        volatile boolean failBetweenPuts = false;
        /** 确认故障确实落在“旧已 RETIRED、新仍 PENDING”的临界瞬间。 */
        volatile boolean parkedAtZeroActiveInstant = false;

        @Override
        protected void betweenSwitchPuts(KeyVersion newActive, Integer retiredVersion) {
            // 此刻直接看底层状态：旧版本已 RETIRED、新版本仍 PENDING（零 ACTIVE 瞬间）
            boolean oldRetired = retiredVersion != null
                    && find(retiredVersion).map(m -> m.state() == KeyState.RETIRED).orElse(false);
            boolean newPending = find(newActive.version())
                    .map(m -> m.state() == KeyState.PENDING).orElse(false);
            parkedAtZeroActiveInstant = oldRetired && newPending;
            reachedMidSwitch.countDown();
            boolean interrupted = false;
            try {
                while (true) {
                    if (release.await(10, TimeUnit.MILLISECONDS)) {
                        break;
                    }
                    LockSupport.parkNanos(1_000_000L);
                }
            } catch (InterruptedException ie) {
                interrupted = true;
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
            if (failBetweenPuts) {
                throw new IllegalStateException(
                        "simulated storage outage between switch writes");
            }
        }
    }

    private KeyManager newManager(ProbeStore store) {
        return new KeyManager(store, new AesGcmCipher(12, 128), new CipherCodec(), 256);
    }

    @Test
    void encryptionNeverFailsWhileRotationIsParkedInsideTheAtomicSwitch() throws Exception {
        ProbeStore store = new ProbeStore();
        KeyManager km = newManager(store);
        km.generateAndActivate();

        // 阶段一（确定性）：轮换前的流量全部落在 v1
        ConcurrentHashMap<String, String> beforeSwitch = new ConcurrentHashMap<>();
        for (int j = 0; j < 200; j++) {
            beforeSwitch.put(km.encrypt("before-" + j), "before-" + j);
        }
        CipherCodec codec = new CipherCodec();
        beforeSwitch.forEach((c, p) -> {
            assertEquals(1, codec.decode(c).keyVersion());
            assertEquals(p, km.decrypt(c));
        });

        int encryptors = 12;
        int attemptsPerEncryptor = 50;
        ExecutorService pool = Executors.newFixedThreadPool(encryptors + 1);
        ConcurrentHashMap<String, String> aroundSwitch = new ConcurrentHashMap<>();
        AtomicInteger failures = new AtomicInteger();

        // 轮换线程停在两次写入之间的临界瞬间（持有 store monitor）
        Future<?> rotation = pool.submit(() -> {
            km.rotate();
            return null;
        });
        assertTrue(store.reachedMidSwitch.await(5, TimeUnit.SECONDS),
                "rotation must park between the two switch writes");

        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> encFutures = new ArrayList<>();
        for (int i = 0; i < encryptors; i++) {
            final int worker = i;
            encFutures.add(pool.submit(() -> {
                go.await();
                for (int j = 0; j < attemptsPerEncryptor; j++) {
                    try {
                        String plain = "around-w" + worker + "-m" + j;
                        aroundSwitch.put(km.encrypt(plain), plain);
                    } catch (RuntimeException ex) {
                        failures.incrementAndGet();
                    }
                }
                return null;
            }));
        }
        go.countDown();

        // 给加密线程时间冲进 current()——它们必然阻塞在 store monitor 上，
        // 等的是同一把锁，因此无论调度如何，释放后看到的都是完整的切换后状态
        Thread.sleep(150);
        store.release.countDown();
        rotation.get(10, TimeUnit.SECONDS);
        for (Future<?> f : encFutures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        assertEquals(0, failures.get(), "no encryption may fail during rotation");
        assertEquals(encryptors * attemptsPerEncryptor, aroundSwitch.size());
        // 临界瞬间没有“没有可用版本”窗口：读者全部在 monitor 上等到切换完成 → 版本 2
        aroundSwitch.forEach((c, p) -> {
            assertEquals(2, codec.decode(c).keyVersion(),
                    "readers parked on the monitor must observe the post-switch ACTIVE v2");
            assertEquals(p, km.decrypt(c), "ciphertext produced during rotation must decrypt");
        });
        // 切换前后两组历史数据都能正确解开
        beforeSwitch.forEach((c, p) -> {
            assertEquals(p, km.decrypt(c));
            assertEquals(KeyState.RETIRED, km.listVersions().get(0).state());
        });
        assertEquals(2, km.currentVersion().version());
        assertEquals(1, km.listVersions().stream().filter(v -> v.state() == KeyState.ACTIVE).count());
        log.info("[concurrency-deterministic] op=ROTATE_PARKED_INSIDE_SWITCH messages={} failures={} basis=ATOMIC_MONITOR_SWITCH result=PASS",
                aroundSwitch.size(), failures.get());
    }

    @Test
    void failureInsideTheSwitchRollsBackWhileConcurrentEncryptionKeepsSucceeding() throws Exception {
        ProbeStore store = new ProbeStore();
        KeyManager km = newManager(store);
        km.generateAndActivate();
        String historical = km.encrypt("historical-data");

        int encryptors = 8;
        ExecutorService pool = Executors.newFixedThreadPool(encryptors + 1);
        ConcurrentHashMap<String, String> aroundFailure = new ConcurrentHashMap<>();
        AtomicInteger failures = new AtomicInteger();

        Future<RotationFailedException> rotation = pool.submit(() ->
                assertThrows(RotationFailedException.class, km::rotate));
        assertTrue(store.reachedMidSwitch.await(5, TimeUnit.SECONDS),
                "rotation must park between the two switch writes");
        // 此时旧版本已被第一次写入转 RETIRED、新版本尚未 ACTIVE；失败回滚必须纠正
        assertTrue(store.parkedAtZeroActiveInstant);

        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> encFutures = new ArrayList<>();
        for (int i = 0; i < encryptors; i++) {
            final int worker = i;
            encFutures.add(pool.submit(() -> {
                go.await();
                for (int j = 0; j < 50; j++) {
                    try {
                        String plain = "rollback-w" + worker + "-m" + j;
                        aroundFailure.put(km.encrypt(plain), plain);
                    } catch (RuntimeException ex) {
                        failures.incrementAndGet();
                    }
                }
                return null;
            }));
        }
        go.countDown();
        Thread.sleep(150);

        // 以存储故障结束挂起的切换：第二次写入不发生，KeyManager 在锁内回滚
        store.failBetweenPuts = true;
        store.release.countDown();
        RotationFailedException thrown = rotation.get(10, TimeUnit.SECONDS);
        assertNotNull(thrown);
        assertEquals("ROTATION_FAILED", thrown.reasonCode());
        assertNotNull(thrown.getCause());
        for (Future<?> f : encFutures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));

        assertEquals(0, failures.get(),
                "encryption must survive a failed-and-rolled-back rotation");

        // 回滚彻底：中间态（两 ACTIVE）被纠正，库中只剩唯一 ACTIVE 的 v1
        assertEquals(1, km.listVersions().size());
        assertEquals(KeyState.ACTIVE, km.listVersions().get(0).state());
        assertEquals(1, km.currentVersion().version());

        // 轮换前历史数据与故障期间新数据全部由 v1 解开
        CipherCodec codec = new CipherCodec();
        assertEquals("historical-data", km.decrypt(historical));
        aroundFailure.forEach((c, p) -> {
            assertEquals(p, km.decrypt(c));
            assertEquals(1, codec.decode(c).keyVersion());
        });

        // 故障解除后干净重试：版本号 2 复用，轮换不再被栅栏挂住
        store.failBetweenPuts = false;
        store.release = new CountDownLatch(1);
        store.release.countDown();
        KeyManager.RotationResult result = km.rotate();
        assertEquals(1, result.previousVersion());
        assertEquals(2, result.active().version());
        assertEquals(1, km.listVersions().stream().filter(v -> v.state() == KeyState.ACTIVE).count());
        assertEquals("historical-data", km.decrypt(historical));
        log.info("[concurrency-deterministic] op=ROTATE_FAIL_INSIDE_SWITCH messages={} failures={} basis=ROLLBACK_RESTORED_ONE_ACTIVE result=PASS",
                aroundFailure.size(), failures.get());
    }
}
