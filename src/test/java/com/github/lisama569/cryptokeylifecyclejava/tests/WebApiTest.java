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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** REST 接口：状态机走查 + 不同失败原因映射不同状态码 + 错误体不含明文。 */
@SpringBootTest
@AutoConfigureMockMvc
class WebApiTest {

    private static final Logger log = LoggerFactory.getLogger(WebApiTest.class);

    @Autowired
    private MockMvc mockMvc;

    @Test
    void fullLifecycleOverHttpYieldsDistinguishableFailuresAndNoPlaintextLeak() throws Exception {
        // 启动时已自动生成 v1：加密
        MvcResult enc = mockMvc.perform(post("/api/keys/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"工资-机密-2026\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyVersion").value(1))
                .andReturn();
        String cipher = Json.field(enc.getResponse().getContentAsString(), "ciphertext");
        log.info("[web] version=1 op=ENCRYPT basis=HTTP_200 result=PASS");

        // 轮换
        mockMvc.perform(post("/api/keys/rotate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.previousVersion").value(1))
                .andExpect(jsonPath("$.activeVersion").value(2));
        log.info("[web] version=1->2 op=ROTATE basis=HTTP_200 result=PASS");

        // 旧数据仍可解密
        mockMvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + cipher + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("工资-机密-2026"))
                .andExpect(jsonPath("$.keyVersion").value(1));
        log.info("[web] version=1 op=DECRYPT_RETIRED basis=HTTP_200 result=PASS");

        // 迁移旧数据
        mockMvc.perform(post("/api/keys/migrate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.completed").value(true))
                .andExpect(jsonPath("$.toVersion").value(2));
        log.info("[web] version=1->2 op=MIGRATE basis=HTTP_200 result=PASS");

        // 吊销 v1（RETIRED -> REVOKED 成功，200）
        mockMvc.perform(post("/api/keys/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":1}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.state").value("REVOKED"));
        log.info("[web] version=1 op=REVOKE basis=HTTP_200 result=ACCEPTED");

        // 重复吊销同一版本 → 409 REVOKED_VERSION，错误体不含明文
        mockMvc.perform(post("/api/keys/revoke")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"version\":1}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("REVOKED_VERSION"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("工资"))));
        log.warn("[web] version=1 op=REVOKE_AGAIN basis=HTTP_409 reason=REVOKED_VERSION result=REJECTED");

        // 已吊销密文解密 → 409 REVOKED_VERSION，错误体不含明文
        mockMvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + cipher + "\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("REVOKED_VERSION"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("工资"))));
        log.warn("[web] version=1 op=DECRYPT basis=HTTP_409 reason=REVOKED_VERSION result=REJECTED");

        // 未知版本 → 404
        String unknown = cipher.replace("v1:", "v77:");
        mockMvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + unknown + "\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("UNKNOWN_VERSION"));
        log.warn("[web] version=77 op=DECRYPT basis=HTTP_404 reason=UNKNOWN_VERSION result=REJECTED");

        // 篡改当前 ACTIVE 版本密文 → 409 INTEGRITY_FAILURE（与 REVOKED_VERSION 可区分）
        MvcResult enc2 = mockMvc.perform(post("/api/keys/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":\"current-secret\"}"))
                .andExpect(status().isOk())
                .andReturn();
        String cipher2 = Json.field(enc2.getResponse().getContentAsString(), "ciphertext");
        char[] chars = cipher2.toCharArray();
        int idx = cipher2.lastIndexOf(':') + 3;
        chars[idx] = chars[idx] == 'A' ? 'B' : 'A';
        mockMvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"ciphertext\":\"" + new String(chars) + "\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("INTEGRITY_FAILURE"));
        log.warn("[web] version=1 op=DECRYPT basis=HTTP_409 reason=INTEGRITY_FAILURE result=REJECTED");

        // 畸形输入 → 400 INVALID_INPUT
        mockMvc.perform(post("/api/keys/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\":null}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_INPUT"));
        mockMvc.perform(post("/api/keys/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("not-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_INPUT"));
        log.warn("[web] version=N/A op=BAD_INPUT basis=HTTP_400 reason=INVALID_INPUT result=REJECTED");

        // 版本清单可核验状态转换
        mockMvc.perform(get("/api/keys/versions"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].state").value("REVOKED"))
                .andExpect(jsonPath("$[1].state").value("ACTIVE"));
        log.info("[web] version=* op=LIST_VERSIONS basis=STATE_AUDITABLE result=PASS");
    }
}
