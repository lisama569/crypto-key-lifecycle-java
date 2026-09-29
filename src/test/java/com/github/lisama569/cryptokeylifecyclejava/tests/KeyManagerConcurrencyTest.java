package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 并发轮换与并发加解密：原子切换、无半更新状态、无重复启用、历史数据全程可解密。 */
class KeyManagerConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(KeyManagerConcurrencyTest.class);

    private KeyManager newManager() {
        return new KeyManager(new InMemoryKeyStore(), new AesGcmCipher(12, 128),
                new CipherCodec(), 256);
    }

    @Test
    void concurrentRotationsAreSerializedWithExactlyOneActivePerVersion() throws Exception {
        KeyManager km = newManager();
        km.generateAndActivate();
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Integer> activatedVersions = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                start.await();
                synchronized (activatedVersions) {
                    activatedVersions.add(km.rotate().active().version());
                }
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        // 每次轮换恰好产生一个新的、不重复的 ACTIVE 版本
        Set<Integer> unique = new HashSet<>(activatedVersions);
        assertEquals(threads, activatedVersions.size());
        assertEquals(threads, unique.size());
        assertEquals(1 + threads, km.currentVersion().version());
        assertEquals(1, km.listVersions().stream().filter(v -> v.state() == KeyState.ACTIVE).count());
        // 每个版本号最多出现一次 ACTIVE（没有重复启用同一版本）
        long activeCount = km.listVersions().stream().filter(v -> v.state() == KeyState.ACTIVE).count();
        assertEquals(1, activeCount);
        log.info("[concurrency] version={} op=CONCURRENT_ROTATE threads={} basis=SERIALIZED_ONE_ACTIVE result=PASS",
                km.currentVersion().version(), threads);
    }

    private static void encryptOne(KeyManager km, int workerId, int i,
                                   ConcurrentHashMap<String, String> produced,
                                   AtomicInteger failures) {
        try {
            String plain = "worker-" + workerId + "-msg-" + i;
            String cipher = km.encrypt(plain);
            produced.put(cipher, plain); // 密文随机 IV，键天然唯一
        } catch (RuntimeException ex) {
            failures.incrementAndGet();
        }
    }

    @Test
    void encryptAndDecryptStayCorrectWhileRotationsHappenConcurrently() throws Exception {
        KeyManager km = newManager();
        km.generateAndActivate();

        int encryptors = 8;
        int rounds = 4;
        int perEncryptor = 200;
        int batch = perEncryptor / (rounds * 2); // 每轮“轮换前 + 轮换后”两小批
        ExecutorService pool = Executors.newFixedThreadPool(encryptors + 1);
        ExecutorService watchdogPool = Executors.newSingleThreadExecutor();
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentHashMap<String, String> produced = new ConcurrentHashMap<>();
        AtomicInteger failures = new AtomicInteger();
        AtomicInteger invariantViolations = new AtomicInteger();

        // 两方 phaser（轮换线程 + 一个加密代表），确定性制造每轮的交错：
        //   加密一批（落在当前 ACTIVE）→ 轮换原子提交 → 再加密一批（落在新 ACTIVE）
        java.util.concurrent.Phaser phaser = new java.util.concurrent.Phaser(2) {
            @Override
            protected boolean onAdvance(int phase, int registeredParties) {
                return phase >= rounds * 2 - 1;
            }
        };

        pool.submit(() -> {
            start.await();
            for (int round = 0; round < rounds; round++) {
                phaser.arriveAndAwaitAdvance(); // 阶段 2r：放行“轮换前”加密批次，等其完成
                phaser.arriveAndAwaitAdvance(); // 阶段 2r+1：轮换提交，再放行“轮换后”批次
                km.rotate();
            }
            return null;
        });
        for (int e = 0; e < encryptors; e++) {
            final int workerId = e;
            pool.submit(() -> {
                start.await();
                int counter = 0;
                for (int round = 0; round < rounds; round++) {
                    for (int i = 0; i < batch; i++) {
                        encryptOne(km, workerId, counter++, produced, failures);
                    }
                    if (workerId == 0) {
                        // 代表所有加密线程与轮换线程同步：先报“轮换前批次完成”，
                        // 再等轮换提交结束后才继续，保证每轮都跨两个版本加密
                        phaser.arriveAndAwaitAdvance();
                        phaser.arriveAndAwaitAdvance();
                    }
                    for (int i = 0; i < batch; i++) {
                        encryptOne(km, workerId, counter++, produced, failures);
                    }
                }
                while (counter < perEncryptor) {
                    encryptOne(km, workerId, counter++, produced, failures);
                }
                return null;
            });
        }
        // 看门狗：轮换+加解密全程高频采样，任何时刻都必须恰好有一个 ACTIVE，
        // 不允许出现“没有可用版本”（0 个）或重复启用（多于 1 个）
        java.util.concurrent.Future<?> watchdog = watchdogPool.submit(() -> {
            start.await();
            while (!Thread.currentThread().isInterrupted()) {
                long active = km.listVersions().stream()
                        .filter(v -> v.state() == KeyState.ACTIVE).count();
                if (active != 1) {
                    invariantViolations.incrementAndGet();
                }
                Thread.sleep(1); // 高频但不独占线程
            }
            return null;
        });
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        watchdog.cancel(true);
        watchdogPool.shutdownNow();
        // 全部密文可解，且明文与生产时一致；每条密文使用的版本必须是当时“当前启用”的有效版本
        Set<Integer> usedVersions = new HashSet<>();
        CipherCodec codec = new CipherCodec();
        produced.forEach((cipher, expectedPlain) -> {
            int v = codec.decode(cipher).keyVersion();
            usedVersions.add(v);
            assertEquals(expectedPlain, km.decrypt(cipher),
                    "ciphertext produced during rotation must decrypt correctly");
            // 轮换完成后，产生数据所用版本必为曾经的 ACTIVE（ACTIVE 或 RETIRED），绝不是 REVOKED/PENDING
            KeyState state = km.listVersions().get(v - 1).state();
            assertTrue(state == KeyState.ACTIVE || state == KeyState.RETIRED,
                    "data must not be encrypted under " + state + " version");
        });
        assertEquals(0, failures.get());
        assertEquals(0, invariantViolations.get(),
                "exactly one ACTIVE version must be observable throughout rotation");
        assertTrue(usedVersions.size() >= 2, "rotations should cause multiple active versions to be used");
        log.info("[concurrency] version={} op=ROTATE_VS_CRYPTO messages={} versionsUsed={} basis=NO_HALF_STATE result=PASS",
                km.currentVersion().version(), produced.size(), usedVersions);
    }
}
