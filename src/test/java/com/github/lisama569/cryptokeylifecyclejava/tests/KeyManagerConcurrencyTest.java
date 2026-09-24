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

    @Test
    void encryptAndDecryptStayCorrectWhileRotationsHappenConcurrently() throws Exception {
        KeyManager km = newManager();
        km.generateAndActivate();

        int encryptors = 8;
        int rotators = 4;
        int perEncryptor = 200;
        ExecutorService pool = Executors.newFixedThreadPool(encryptors + rotators);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentHashMap<String, String> produced = new ConcurrentHashMap<>();
        AtomicInteger failures = new AtomicInteger();

        for (int r = 0; r < rotators; r++) {
            pool.submit(() -> {
                start.await();
                km.rotate();
                return null;
            });
        }
        for (int e = 0; e < encryptors; e++) {
            final int workerId = e;
            pool.submit(() -> {
                start.await();
                for (int i = 0; i < perEncryptor; i++) {
                    try {
                        String plain = "worker-" + workerId + "-msg-" + i;
                        String cipher = km.encrypt(plain);
                        produced.put(cipher, plain); // 密文随机 IV，键天然唯一
                    } catch (RuntimeException ex) {
                        failures.incrementAndGet();
                    }
                }
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));

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
        assertTrue(usedVersions.size() >= 2, "rotations should cause multiple active versions to be used");
        log.info("[concurrency] version={} op=ROTATE_VS_CRYPTO messages={} versionsUsed={} basis=NO_HALF_STATE result=PASS",
                km.currentVersion().version(), produced.size(), usedVersions);
    }
}
