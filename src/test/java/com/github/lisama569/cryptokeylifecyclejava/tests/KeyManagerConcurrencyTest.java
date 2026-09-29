package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.SecretKey;
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

    /**
     * 确定性钉住轮换中间点：让“旧 ACTIVE -&gt; RETIRED”落库后阻塞，直到测试放行。
     * 与 {@link RotationConcurrencyTest} 中同款，用于保证写入在切换前后都真实发生，
     * 不依赖线程调度碰运气。
     */
    private static final class ParkedStore implements KeyStore {
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
            delegate.updateState(meta);
            if (armed && meta.state() == KeyState.RETIRED) {
                reached.countDown();
                try {
                    release.await(30, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
            }
        }
    }

    @Test
    void encryptAndDecryptStayCorrectWhileRotationsHappenConcurrently() throws Exception {
        ParkedStore store = new ParkedStore();
        KeyManager km = new KeyManager(store, new AesGcmCipher(12, 128),
                new CipherCodec(), 256);
        km.generateAndActivate();

        int encryptors = 8;
        int perEncryptor = 200;
        ExecutorService pool = Executors.newCachedThreadPool();
        ConcurrentHashMap<String, String> produced = new ConcurrentHashMap<>();
        AtomicInteger failures = new AtomicInteger();
        try {
            // 0) 轮换开始前先写一批：此时唯一在用版本是 v1，确定性地产生 v1 密文
            for (int i = 0; i < 200; i++) {
                String plain = "before-" + i;
                produced.put(km.encrypt(plain), plain);
            }

            // 1) 第一轮轮换精确停在切换窗口，全部写入线程此刻启动：
            //    修复后它们在写锁上排队，放行后拿到 v2，确定性地产生 v2 密文
            Future<KeyManager.RotationResult> firstRotation = pool.submit(km::rotate);
            assertTrue(store.reached.await(5, TimeUnit.SECONDS));

            CountDownLatch writersStart = new CountDownLatch(1);
            List<Future<?>> writers = new ArrayList<>();
            for (int e = 0; e < encryptors; e++) {
                final int workerId = e;
                writers.add(pool.submit(() -> {
                    writersStart.await();
                    for (int i = 0; i < perEncryptor; i++) {
                        try {
                            String plain = "worker-" + workerId + "-msg-" + i;
                            produced.put(km.encrypt(plain), plain); // 密文随机 IV，键天然唯一
                        } catch (RuntimeException ex) {
                            failures.incrementAndGet();
                        }
                    }
                    return null;
                }));
            }
            writersStart.countDown();
            // 让写入线程确实在写锁上排起队，再放行切换（不影响正确性，仅提高排队的确定性）
            Thread.sleep(200);
            store.release.countDown();
            assertEquals(2, firstRotation.get(5, TimeUnit.SECONDS).active().version());

            // 2) 排队写入完成后，再并发执行多次轮换与新一轮写入，形成交错压力
            int extraRotations = 3;
            List<Future<?>> rotators = new ArrayList<>();
            for (int r = 0; r < extraRotations; r++) {
                rotators.add(pool.submit(km::rotate));
            }
            for (Future<?> w : writers) {
                w.get(30, TimeUnit.SECONDS);
            }
            for (Future<?> rot : rotators) {
                rot.get(30, TimeUnit.SECONDS);
            }

            // 全部密文可解，且明文与生产时一致；每条密文使用的版本必须是曾经的 ACTIVE（ACTIVE/RETIRED）
            Set<Integer> usedVersions = new HashSet<>();
            CipherCodec codec = new CipherCodec();
            produced.forEach((cipher, expectedPlain) -> {
                int v = codec.decode(cipher).keyVersion();
                usedVersions.add(v);
                assertEquals(expectedPlain, km.decrypt(cipher),
                        "ciphertext produced during rotation must decrypt correctly");
                KeyState state = km.listVersions().get(v - 1).state();
                assertTrue(state == KeyState.ACTIVE || state == KeyState.RETIRED,
                        "data must not be encrypted under " + state + " version");
            });
            assertEquals(0, failures.get());
            // 确定性保证：切换窗口两侧都有写入落盘，因此一定用过至少两个版本
            assertTrue(usedVersions.contains(1) && usedVersions.contains(2),
                    "writes parked across the switch must use both v1 and v2, got " + usedVersions);
            assertTrue(usedVersions.size() >= 2, "rotations should cause multiple versions to be used");
            log.info("[concurrency] version={} op=ROTATE_VS_CRYPTO messages={} versionsUsed={} basis=NO_HALF_STATE result=PASS",
                    km.currentVersion().version(), produced.size(), usedVersions);
        } finally {
            store.release.countDown();
            pool.shutdownNow();
        }
    }
}
