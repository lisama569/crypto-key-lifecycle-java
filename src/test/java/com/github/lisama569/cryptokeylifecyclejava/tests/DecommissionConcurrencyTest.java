package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyState;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.VersionInUseException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionLifecycleService;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 安全下线的并发竞争：同一版本只有一个成功者；下线与定向清理并发时不出现半停用。 */
class DecommissionConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(DecommissionConcurrencyTest.class);

    private KeyManager newKeyManager() {
        KeyManager km = new KeyManager(new InMemoryKeyStore(), new AesGcmCipher(12, 128),
                new CipherCodec(), 256);
        km.generateAndActivate();
        return km;
    }

    @Test
    void concurrentDecommissionOfSameVersionHasExactlyOneWinner() throws Exception {
        KeyManager km = newKeyManager();
        InMemoryDataRepository repo = new InMemoryDataRepository();
        VersionLifecycleService lifecycle = new VersionLifecycleService(km, repo);
        km.rotate(); // v1 RETIRED, 无引用

        int workers = 16;
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger successes = new AtomicInteger();
        ConcurrentLinkedQueue<String> rejectReasons = new ConcurrentLinkedQueue<>();
        for (int w = 0; w < workers; w++) {
            pool.submit(() -> {
                start.await();
                try {
                    lifecycle.decommission(1);
                    successes.incrementAndGet();
                } catch (RevokedVersionException e) {
                    rejectReasons.add(e.reasonCode());
                }
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        assertEquals(1, successes.get(), "exactly one concurrent decommission may succeed");
        assertEquals(workers - 1, rejectReasons.size());
        rejectReasons.forEach(r -> assertEquals("REVOKED_VERSION", r,
                "losers must get the consistent conflict reason"));
        assertEquals(KeyState.REVOKED, km.listVersions().stream()
                .filter(v -> v.version() == 1).findFirst().orElseThrow().state());
        log.info("[decommission-concurrency] version=1 op=DECOMMISSION basis=SINGLE_WINNER workers={} result=PASS",
                workers);
    }

    @Test
    void decommissionRacingTargetedCleanupNeverLeavesUndecryptableData() throws Exception {
        KeyManager km = newKeyManager();
        InMemoryDataRepository repo = new InMemoryDataRepository();
        MigrationService migration = new MigrationService(km, repo);
        VersionLifecycleService lifecycle = new VersionLifecycleService(km, repo);

        int total = 600;
        for (int i = 0; i < total; i++) {
            repo.save(new DataRecord("c-" + i, km.encrypt("c-" + i), 1, RecordStatus.CURRENT));
        }
        km.rotate(); // v1 RETIRED(600 refs), v2 ACTIVE

        AtomicInteger blockedCount = new AtomicInteger();
        AtomicInteger decommissioned = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);

        // 线程 A：分批定向清理 v1，直到收敛
        Thread cleaner = new Thread(() -> {
            awaitQuietly(start);
            while (!migration.migrateFromVersion(1, 25).completed()) {
                Thread.yield();
            }
        });
        // 线程 B：并发反复尝试下线 v1；成功时必须已经引用清零
        Thread decommissioner = new Thread(() -> {
            awaitQuietly(start);
            while (decommissioned.get() == 0) {
                try {
                    lifecycle.decommission(1);
                    decommissioned.incrementAndGet();
                    // 成功瞬间：引用必须已经清零（门禁在锁内判定）
                    assertEquals(0, lifecycle.statsFor(1).referenceCount(),
                            "decommission succeeded while references remained");
                } catch (VersionInUseException e) {
                    blockedCount.incrementAndGet();
                    Thread.yield();
                }
            }
        });
        cleaner.start();
        decommissioner.start();
        start.countDown();
        cleaner.join(30_000);
        decommissioner.join(30_000);

        assertEquals(1, decommissioned.get(), "decommission eventually succeeds after cleanup");
        assertTrue(blockedCount.get() > 0, "decommission must have been blocked while references existed");
        assertEquals(KeyState.REVOKED, km.listVersions().stream()
                .filter(v -> v.version() == 1).findFirst().orElseThrow().state());
        // 终态核验：版本已下线，且不存在打不开的旧数据——全部记录已在 v2 且明文正确
        assertEquals(0, lifecycle.statsFor(1).referenceCount());
        List<DataRecord> all = repo.findAll();
        assertEquals(total, all.size());
        all.forEach(r -> {
            assertEquals(2, r.keyVersion());
            assertEquals("c-" + r.id().substring(2), km.decrypt(r.ciphertext()));
        });
        log.info("[decommission-concurrency] version=1 op=DECOMMISSION+CLEANUP basis=NO_HALF_DECOMMISSION blocked={} total={} result=PASS",
                blockedCount.get(), total);
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
