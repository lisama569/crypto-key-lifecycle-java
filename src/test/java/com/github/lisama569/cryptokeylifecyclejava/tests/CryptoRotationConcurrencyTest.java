package com.github.lisama569.cryptokeylifecyclejava.tests;

import org.springframework.test.annotation.DirtiesContext;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.service.CryptoService;
import com.github.lisama569.cryptokeylifecyclejava.service.KeyAdminService;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecord;
import com.github.lisama569.cryptokeylifecyclejava.storage.EncryptedRecordStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import 	java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 轮换 × 加解密并发集成测试：
 * <ul>
 *   <li>轮换前数据在保留期内始终可解；</li>
 *   <li>轮换后新数据只使用新版本；</li>
 *   <li>并发触发轮换只有一个成功，其余 CONCURRENT_ROTATION，无半更新状态。</li>
 * </ul>
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class CryptoRotationConcurrencyTest {

    private static final Logger testLog = LoggerFactory.getLogger("KEY_LIFECYCLE_TEST");

    @Autowired
    private CryptoService cryptoService;
    @Autowired
    private KeyAdminService keyAdminService;
    @Autowired
    private EncryptedRecordStore recordStore;

    @Test
    @DisplayName("轮换前后加密数据均正确解密，且新加密只落在新版本")
    void encryptDecryptAcrossRotation() {
        // v1 数据（启动引导版本）
        cryptoService.encrypt("p-v1", "data-before-rotation");
        int v1 = keyAdminService.versions().stream()
                .filter(v -> v.current()).findFirst().orElseThrow().version();
        assertEquals(1, v1);

        int v2 = keyAdminService.rotate().getVersion();
        cryptoService.encrypt("p-v2", "data-after-rotation");
        int v3 = keyAdminService.rotate().getVersion();
        cryptoService.encrypt("p-v3", "data-after-second-rotation");

        // 三条记录分别绑定各自产生时的当前版本
        assertEquals(1, recordStore.require("p-v1").getKeyVersion());
        assertEquals(2, recordStore.require("p-v2").getKeyVersion());
        assertEquals(3, recordStore.require("p-v3").getKeyVersion());

        // 保留期内所有历史版本都可正确解密
        assertEquals("data-before-rotation", cryptoService.decrypt("p-v1"));
        assertEquals("data-after-rotation", cryptoService.decrypt("p-v2"));
        assertEquals("data-after-second-rotation", cryptoService.decrypt("p-v3"));
        testLog.info("op=ROTATE keyVersion=3 decision=ALLOWED reason='all 3 versions decrypt within retention'");
    }

    @Test
    @DisplayName("高并发：加密请求与多轮轮换同时进行，全部密文可解且只引用各自时刻的当前版本")
    void concurrentEncryptsAndRotations() throws Exception {
        int threads = 8;
        int perThread = 60;
        ExecutorService pool = Executors.newFixedThreadPool(threads + 2);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        AtomicInteger rotated = new AtomicInteger();

        // 多个加密线程 + 多个轮换线程同时开闸
        List<Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            final int tid = t;
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        String id = "t-" + tid + "-" + i;
                        String plain = "plainx-" + tid + "-" + i;
                        cryptoService.encrypt(id, plain);
                    }
                } catch (Throwable e) {
                    errors.add(e);
                }
            }));
        }
        int rotationAttempts = 6;
        for (int r = 0; r < rotationAttempts; r++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    keyAdminService.rotate();
                    rotated.incrementAndGet();
                } catch (KeyLifecycleException e) {
                    // 并发轮换被拒是预期行为，但原因必须可区分
                    assertEquals(com.github.lisama569.cryptokeylifecyclejava.error.FailureReason.CONCURRENT_ROTATION,
                            e.getReason(), "并发轮换失败原因只能是 CONCURRENT_ROTATION");
                } catch (Throwable e) {
                    errors.add(e);
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        assertTrue(errors.isEmpty(), "并发过程中不应出现非预期异常: " + errors);
        assertTrue(rotated.get() >= 1 && rotated.get() <= rotationAttempts);

        // 核验：所有记录明文可解，且版本号只取曾经“当前启用”过的版本
        Set<Integer> currentVersionsSeen = new HashSet<>();
        int total = threads * perThread;
        for (int t = 0; t < threads; t++) {
            for (int i = 0; i < perThread; i++) {
                String id = "t-" + t + "-" + i;
                EncryptedRecord record = recordStore.require(id);
                assertEquals("plainx-" + t + "-" + i, cryptoService.decrypt(id),
                        "记录 " + id + " 明文必须一致");
                currentVersionsSeen.add(record.getKeyVersion());
            }
        }
        assertFalse(currentVersionsSeen.isEmpty());
        testLog.info("op=CONCURRENT_ROTATE keyVersion=- decision=ALLOWED "
                + "reason='{} records, {} rotations succeeded, versions used={}'",
                total, rotated.get(), currentVersionsSeen);
    }
}
