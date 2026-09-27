package com.github.lisama569.cryptokeylifecyclejava.tests;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** 新增 REST 端点：引用预检、安全下线门禁、定向清理的状态码与原因码。 */
@SpringBootTest
@AutoConfigureMockMvc
class DecommissionWebApiTest {

    private static final Logger log = LoggerFactory.getLogger(DecommissionWebApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void referencePrecheckGateAndTargetedCleanupOverHttp() throws Exception {
        // 先轮换一次，取得“旧版本 P / 当前版本 A”（版本号取决于上下文执行顺序，动态读取）
        MvcResult rot = mockMvc.perform(post("/api/keys/rotate"))
                .andExpect(status().isOk()).andReturn();
        JsonNode rotateBody = MAPPER.readTree(rot.getResponse().getContentAsString());
        int active = rotateBody.get("activeVersion").asInt();
        int previous = rotateBody.get("previousVersion").asInt();

        // 引用预检：当前服务版本被 CURRENTLY_ACTIVE 挡住
        mockMvc.perform(get("/api/keys/versions/" + active + "/references"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canDecommission").value(false))
                .andExpect(jsonPath("$.blockedReason").value("CURRENTLY_ACTIVE"))
                .andExpect(jsonPath("$.references").value(0))
                .andExpect(jsonPath("$.activeVersion").value(active));
        log.info("[web] version={} op=INSPECT basis=CURRENTLY_ACTIVE result=PASS", active);

        // 旧版本引用为零、RETIRED：可安全下线
        mockMvc.perform(get("/api/keys/versions/" + previous + "/references"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canDecommission").value(true))
                .andExpect(jsonPath("$.blockedReason").doesNotExist())
                .andExpect(jsonPath("$.state").value("RETIRED"));
        log.info("[web] version={} op=INSPECT basis=DECOMMISSIONABLE result=PASS", previous);

        // 预检未知版本 → 404
        mockMvc.perform(get("/api/keys/versions/999/references"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("UNKNOWN_VERSION"));

        // 下线当前服务版本 → 409 VERSION_ACTIVE
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"version\":" + active + "}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("VERSION_ACTIVE"));
        log.warn("[web] version={} op=DECOMMISSION basis=HTTP_409 reason=VERSION_ACTIVE result=REJECTED", active);

        // 缺少 version 字段 → 400
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_INPUT"));

        // 下线未知版本 → 404（与状态冲突区分）
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"version\":999}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("UNKNOWN_VERSION"));

        // 正常下线旧版本 → 200 DECOMMISSIONED
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"version\":" + previous + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("DECOMMISSIONED"));
        log.info("[web] version={} op=DECOMMISSION basis=HTTP_200 result=ACCEPTED", previous);

        // 重复下线 → 409 VERSION_DECOMMISSIONED（一致冲突）
        mockMvc.perform(post("/api/keys/decommission")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"version\":" + previous + "}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("VERSION_DECOMMISSIONED"));
        // 预检也给一致结论
        mockMvc.perform(post("/api/keys/decommission/preflight")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"version\":" + previous + "}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.canDecommission").value(false))
                .andExpect(jsonPath("$.blockedReason").value("ALREADY_DECOMMISSIONED"));
        log.warn("[web] version={} op=DECOMMISSION basis=HTTP_409 reason=VERSION_DECOMMISSIONED result=REJECTED", previous);

        // 定向清理：当前 ACTIVE 作为来源 → 409；未知版本 → 404；已下线版本无引用 → completed
        mockMvc.perform(post("/api/keys/migrate/version").param("version", String.valueOf(active)))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("KEY_STATE_CONFLICT"));
        mockMvc.perform(post("/api/keys/migrate/version").param("version", "999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("UNKNOWN_VERSION"));
        mockMvc.perform(post("/api/keys/migrate/version").param("version", String.valueOf(previous)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.completed").value(true))
                .andExpect(jsonPath("$.remaining").value(0));
        log.info("[web] version={} op=TARGETED_CLEANUP basis=NO_REFERENCES result=PASS", previous);
    }
}
