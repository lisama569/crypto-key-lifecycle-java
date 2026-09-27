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
import com.github.lisama569.cryptokeylifecyclejava.decommission.MaintenanceLock;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionDecommissionService;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceService;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 安全下线并发：同一版本同时下线只允许一个成功；清理与下线竞争不产生“已下线但打不开”。 */
class DecommissionConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(DecommissionConcurrencyTest.class);

    private static final class Fixture {
        final KeyManager km = new KeyManager(new InMemoryKeyStore(),
                new AesGcmCipher(12, 128), new CipherCodec(), 256);
        final InMemoryDataRepository repo = new InMemoryDataRepository();
        final MaintenanceLock lock = new MaintenanceLock();
        final MigrationService migration = new MigrationService(km, repo, lock);
        final VersionReferenceService refs = new VersionReferenceService(km, repo, lock);
        final VersionDecommissionService decom =
                new VersionDecommissionService(km, repo, lock, refs);
    }

    @Test
    void concurrentDecommissionOfSameVersionHasExactlyOneWinner() throws Exception {
        Fixture f = new Fixture();
        f.km.generateAndActivate();
        f.km.rotate(); // v2 active；v1 retired 且没有任何引用

        int threads = 8;
        CyclicBarrier barrier = new CyclicBarrier(threads);
        CountDownLatch done = new CountDownLatch(threads);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        AtomicInteger accepted = new AtomicInteger();
        ConcurrentLinkedQueue<String> rejectReasons = new ConcurrentLinkedQueue<>();

        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    barrier.await(5, TimeUnit.SECONDS);
                    f.decom.decommission(1);
                    accepted.incrementAndGet();
                } catch (KeyLifecycleException ex) {
                    rejectReasons.add(ex.reasonCode());
                } catch (Exception unexpected) {
                    rejectReasons.add("UNEXPECTED:" + unexpected.getClass().getSimpleName());
                } finally {
                    done.countDown();
                }
            });
        }
        assertTrue(done.await(20, TimeUnit.SECONDS), "all decommission attempts must finish");
        pool.shutdownNow();

        assertEquals(1, accepted.get(), "exactly one decommission may succeed");
        assertEquals(threads - 1, rejectReasons.size());
        // 其余全部得到一致、可区分的冲突结果
        rejectReasons.forEach(reason ->
                assertEquals("VERSION_DECOMMISSIONED", reason, "losers must see a consistent conflict"));
        assertEquals(KeyState.DECOMMISSIONED, f.km.getVersion(1).state());
        log.info("[concurrency] version=1 op=DECOMMISSION_RACE threads=8 winners=1 losers=7 reason=VERSION_DECOMMISSIONED result=PASS");
    }

    @Test
    void cleanupRacingWithDecommissionNeverLeavesOrphanedData() throws Exception {
        Fixture f = new Fixture();
        f.km.generateAndActivate(); // v1
        for (int i = 0; i < 1000; i++) {
            f.repo.save(new DataRecord("r" + i, f.km.encrypt("m#" + i), 1, RecordStatus.CURRENT));
        }
        f.km.rotate(); // v2 active, v1 retired 且 1000 条引用

        // 引用 1000 时先做一次确定性的下线尝试：必须被“仍被引用”门禁挡住，版本保持 RETIRED
        KeyLifecycleException firstBlock = assertThrows(KeyLifecycleException.class,
                () -> f.decom.decommission(1));
        assertEquals("VERSION_STILL_REFERENCED", firstBlock.reasonCode());
        assertEquals(KeyState.RETIRED, f.km.getVersion(1).state());
        ConcurrentLinkedQueue<String> rejectReasons = new ConcurrentLinkedQueue<>();
        rejectReasons.add(firstBlock.reasonCode());

        // 清理方：小批量反复跑，直到该来源版本引用清零
        Thread cleaner = new Thread(() -> {
            while (f.refs.inspect(1).references() > 0) {
                f.migration.migrateVersion(1, 25);
            }
        }, "targeted-cleaner");

        // 下线方：与清理并发地持续重试；引用未清时被稳定拒绝，清零后恰好成功一次
        AtomicInteger accepted = new AtomicInteger();
        Thread decommissioner = new Thread(() -> {
            while (accepted.get() == 0) {
                try {
                    f.decom.decommission(1);
                    accepted.incrementAndGet();
                } catch (KeyLifecycleException ex) {
                    rejectReasons.add(ex.reasonCode());
                }
            }
        }, "decommissioner");

        cleaner.start();
        decommissioner.start();
        cleaner.join(20_000);
        decommissioner.join(20_000);
        assertFalse(cleaner.isAlive(), "cleaner should finish");
        assertFalse(decommissioner.isAlive(), "decommissioner should finish");

        assertEquals(1, accepted.get());
        assertEquals(KeyState.DECOMMISSIONED, f.km.getVersion(1).state());
        // 成功之前的所有拒绝只能是“仍被引用”这一个可区分原因，且至少观察到一次
        assertFalse(rejectReasons.isEmpty(), "decommission must have been blocked while references existed");
        rejectReasons.forEach(reason ->
                assertEquals("VERSION_STILL_REFERENCED", reason));

        // 最终不变量：库里不存在仍指向已下线版本的记录；全部数据可在 v2 解开
        f.repo.findAll().forEach(r -> {
            assertEquals(2, r.keyVersion(), "no stored data may still reference a decommissioned version");
            assertEquals("m#" + r.id().substring(1), f.km.decrypt(r.ciphertext()));
        });
        log.info("[concurrency] version=1 op=CLEANUP_VS_DECOMMISSION records=1000 rejections={} finalState=DECOMMISSIONED orphaned=0 result=PASS",
                rejectReasons.size());
    }
}
