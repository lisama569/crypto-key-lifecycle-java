package com.github.lisama569.cryptokeylifecyclejava.tests;

import org.springframework.test.annotation.DirtiesContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * REST 面测试：成功路径、可区分的错误原因码与 HTTP 状态、
 * 异常输入返回 4xx 而非 500、错误响应不泄露明文。
 */
@SpringBootTest
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@AutoConfigureMockMvc
class KeyLifecycleControllerTest {

    private static final Logger testLog = LoggerFactory.getLogger("KEY_LIFECYCLE_TEST");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyLifecycleManager keyLifecycleManager;

    @Test
    @DisplayName("写入加密 → 轮换 → 旧数据可读；吊销前需迁移的完整 HTTP 流程")
    void fullLifecycleOverHttp() throws Exception {
        mockMvc.perform(post("/api/data/sec-1").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"topsecret\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyVersion").value(1))
                .andExpect(jsonPath("$.plaintext").doesNotExist()); // 写响应不含明文

        mockMvc.perform(get("/api/data/sec-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("topsecret"));

        mockMvc.perform(post("/api/keys/rotate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyVersion").value(2));

        // 新数据只使用 v2
        mockMvc.perform(post("/api/data/sec-2").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"newsecret\"}"))
                .andExpect(jsonPath("$.keyVersion").value(2));
        // 旧版本数据保留期内仍可解
        mockMvc.perform(get("/api/data/sec-1")).andExpect(jsonPath("$.plaintext").value("topsecret"));

        // v1 仍有引用 -> 409 REFERENCES_REMAIN，且错误文案不泄露明文
        mockMvc.perform(post("/api/keys/1/revoke"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.reason").value("REFERENCES_REMAIN"))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("topsecret"))));

        // 迁移后吊销成功
        mockMvc.perform(post("/api/migrations").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fromVersion\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.remainingByVersion").value(0));
        mockMvc.perform(post("/api/keys/1/revoke")).andExpect(status().isOk());

        // 列出密钥：v1 REVOKED, v2 ENABLED(current)
        mockMvc.perform(get("/api/keys"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].version").value(1))
                .andExpect(jsonPath("$[0].state").value("REVOKED"))
                .andExpect(jsonPath("$[1].state").value("ENABLED"))
                .andExpect(jsonPath("$[1].current").value(true));
        testLog.info("op=HTTP_LIFECYCLE keyVersion=2 decision=ALLOWED reason='rotate/migrate/revoke over REST verified'");
    }

    @Test
    @DisplayName("并发轮换 HTTP：一个 200，其余 409 CONCURRENT_ROTATION")
    void concurrentRotationOverHttp() throws Exception {
        int threads = 8;
        java.util.List<java.util.concurrent.Future<Integer>> results = new java.util.ArrayList<>();
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(threads);
        var latch = new java.util.concurrent.CountDownLatch(1);
        // 确定性放大轮换临界区，使 8 个请求真正交叠在同一次轮换窗口
        keyLifecycleManager.setRotationCommitHook(() -> {
            try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        });
        for (int i = 0; i < threads; i++) {
            results.add(pool.submit(() -> {
                latch.await();
                return mockMvc.perform(post("/api/keys/rotate")).andReturn().getResponse().getStatus();
            }));
        }
        latch.countDown();
        long ok = 0;
        long conflict = 0;
        for (var f : results) {
            int status = f.get();
            if (status == 200) {
                ok++;
            } else if (status == 409) {
                conflict++;
            } else {
                throw new AssertionError("意外状态码 " + status);
            }
        }
        pool.shutdown();
        keyLifecycleManager.setRotationCommitHook(null);
        assertEquals(1, ok, "恰好一次轮换成功");
        assertEquals(threads - 1L, conflict, "其余全部 409");
        testLog.info("op=ROTATE keyVersion=- decision=ALLOWED reason='1 ok + {} concurrent rejections'", conflict);
    }

    @Test
    @DisplayName("异常输入：缺字段/坏 JSON/未知记录 → 4xx，服务不返回 500")
    void invalidInputsReturn4xx() throws Exception {
        mockMvc.perform(post("/api/data/x").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_INPUT"));

        mockMvc.perform(post("/api/data/x").contentType(MediaType.APPLICATION_JSON).content("{not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_INPUT"));

        mockMvc.perform(post("/api/data/x").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_INPUT"));

        mockMvc.perform(get("/api/data/missing"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_INPUT"));

        mockMvc.perform(post("/api/keys/999/revoke"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.reason").value("UNKNOWN_VERSION"));

        mockMvc.perform(post("/api/migrations").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.reason").value("INVALID_INPUT"));
        testLog.info("op=HTTP_INVALID keyVersion=- decision=REJECTED reason='all malformed inputs mapped to 4xx'");
    }

    private static void assertEquals(long expected, long actual, String msg) {
        org.junit.jupiter.api.Assertions.assertEquals(expected, actual, msg);
    }
}
