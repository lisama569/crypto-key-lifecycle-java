package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

/** 引用统计、定向清理与安全下线的 REST 走查：结论与失败原因在 HTTP 层可区分。 */
@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_CLASS)
class WebDecommissionApiTest {

    private static final Logger log = LoggerFactory.getLogger(WebDecommissionApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private com.github.lisama569.cryptokeylifecyclejava.migration.DataRepository repository;

    @Test
    void referenceStatsTargetedCleanupAndGuardedDecommissionOverHttp() throws Exception {
        // 造一条 v1 数据（密文来自 /encrypt，由业务侧登记入库）后轮换到 v2
        var enc = mockMvc.perform(post("/api/keys/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"decommission-me\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String cipher = Json.field(enc.getResponse().getContentAsString(), "ciphertext");
        repository.save(new com.github.lisama569.cryptokeylifecyclejava.migration.DataRecord(
                "web-1", cipher, 1,
                com.github.lisama569.cryptokeylifecyclejava.migration.RecordStatus.CURRENT));
        mockMvc.perform(post("/api/keys/rotate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeVersion").value(2));

        // 引用统计：v1 被数据引用挡住，v2 因是在用版本被挡，两者原因可区分
        mockMvc.perform(get("/api/keys/versions/1/references"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.referenceCount").value(1))
                .andExpect(jsonPath("$.safeToDecommission").value(false))
                .andExpect(jsonPath("$.reason").value("BLOCKED_BY_REFERENCES"));
        mockMvc.perform(get("/api/keys/versions/2/references"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.reason").value("BLOCKED_ACTIVE_VERSION"));
        log.info("[web] version=1,2 op=REFERENCES basis=HTTP_200_DISTINCT_REASONS result=PASS");

        // 未知版本统计 → 404
        mockMvc.perform(get("/api/keys/versions/99/references"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("UNKNOWN_VERSION"));

        // 门禁：仍被引用 → 409 VERSION_STILL_REFERENCED；当前在用 → 409 VERSION_IS_ACTIVE
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":1}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("VERSION_STILL_REFERENCED"));
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":2}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("VERSION_IS_ACTIVE"));
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":99}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("UNKNOWN_VERSION"));
        log.warn("[web] op=DECOMMISSION basis=HTTP_409/404 reason=DISTINCT result=REJECTED");

        // 定向清理 v1 → 引用收敛为零
        mockMvc.perform(post("/api/keys/migrate/from/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fromVersion").value(1))
                .andExpect(jsonPath("$.toVersion").value(2))
                .andExpect(jsonPath("$.completed").value(true))
                .andExpect(jsonPath("$.remaining").value(0));
        mockMvc.perform(get("/api/keys/versions/1/references"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.referenceCount").value(0))
                .andExpect(jsonPath("$.safeToDecommission").value(true))
                .andExpect(jsonPath("$.reason").value("SAFE_TO_DECOMMISSION"));
        log.info("[web] version=1 op=CLEANUP+REFERENCES basis=CONVERGED result=PASS");

        // 下线放行；重复提交 → 409 REVOKED_VERSION
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("REVOKED"));
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":1}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("REVOKED_VERSION"));
        log.info("[web] version=1 op=DECOMMISSION basis=HTTP_200_THEN_409 result=PASS");

        // 全量统计快照可核验
        mockMvc.perform(get("/api/keys/references"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].reason").value("ALREADY_DECOMMISSIONED"))
                .andExpect(jsonPath("$[1].reason").value("BLOCKED_ACTIVE_VERSION"));
        log.info("[web] op=REFERENCES basis=SNAPSHOT_AUDITABLE result=PASS");
    }
}
