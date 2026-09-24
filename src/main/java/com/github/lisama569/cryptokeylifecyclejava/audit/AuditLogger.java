package com.github.lisama569.cryptokeylifecyclejava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 审计日志：统一打印密钥版本、操作类型与判定依据（decision/reason）。
 * 日志中不得出现明文或密钥材料——调用方也不得把这些内容传入。
 */
@Component
public class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger("KEY_LIFECYCLE_AUDIT");

    /**
     * @param operation  操作类型，例如 ENCRYPT / DECRYPT / ROTATE / ENABLE / REVOKE / MIGRATE
     * @param keyVersion 涉及的密钥版本（可为 null，表示与具体版本无关）
     * @param decision   判定结论，例如 ALLOWED / REJECTED / RETIRED / COMPLETED
     * @param reason     判定依据，例如状态、失败原因或补充说明
     */
    public void log(String operation, Integer keyVersion, String decision, String reason) {
        log.info("op={} keyVersion={} decision={} reason='{}'", operation,
                keyVersion == null ? "-" : keyVersion, decision, reason);
    }
}
