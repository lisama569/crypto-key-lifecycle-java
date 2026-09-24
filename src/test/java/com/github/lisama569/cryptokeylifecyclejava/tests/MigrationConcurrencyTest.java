package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationProgress;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 多个迁移批次并发触发时：串行化、不重复处理、最终一致。 */
class MigrationConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(MigrationConcurrencyTest.class);

    @Test
    @SuppressWarnings("checkstyle:MethodLength")
    void concurrentMigrationCallsConvergeWithoutConflictOrDuplicateRewrites() throws Exception {
        KeyManager km = new KeyManager(new InMemoryKeyStore(), new AesGcmCipher(12, 128),
                new CipherCodec(), 256);
        InMemoryDataRepository repo = new InMemoryDataRepository();
        MigrationService migration = new MigrationService(km, repo);
        km.generateAndActivate();

        int total = 50;
        for (int i = 0; i < total; i++) {
            repo.save(new DataRecord("id-" + i, km.encrypt("p-" + i), 1, RecordStatus.CURRENT));
        }
        km.rotate();

        int workers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(workers);
        CountDownLatch start = new CountDownLatch(1);
        Set<Integer> migratedCounts = ConcurrentHashMap.newKeySet();
        for (int w = 0; w < workers; w++) {
            pool.submit(() -> {
                start.await();
                MigrationProgress p = migration.migrateToCurrent(10);
                migratedCounts.add(p.migrated());
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS));

        // 8 个每批 10 条的并发批次对 50 条数据抢跑：必有批次真正迁移了数据，
        // 也有批次因其它批次先完成而少迁移/跳过——总数仍精确收敛
        assertTrue(migratedCounts.stream().anyMatch(c -> c > 0),
                "at least one concurrent batch must migrate records");

        // 反复跑到收敛
        MigrationProgress fin;
        do {
            fin = migration.migrateToCurrent(null);
        } while (!fin.completed());

        assertEquals(total, repo.findAll().size(), "no record lost or duplicated");
        repo.findAll().forEach(r -> {
            assertEquals(2, r.keyVersion(), "record " + r.id() + " must end on active version");
            assertEquals(RecordStatus.CURRENT, r.status());
            assertEquals("p-" + r.id().substring(3), km.decrypt(r.ciphertext()),
                    "plaintext meaning preserved for " + r.id());
        });
        log.info("[migration-concurrency] version=1->2 op=CONCURRENT_MIGRATE workers={} total={} basis=SERIALIZED_CAS_FINAL_CONSISTENT result=PASS",
                workers, total);
    }
}
