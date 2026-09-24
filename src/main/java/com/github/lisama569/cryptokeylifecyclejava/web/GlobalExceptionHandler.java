package com.github.lisama569.cryptokeylifecyclejava.web;

import com.github.lisama569.cryptokeylifecyclejava.error.FailureReason;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.http.ResponseEntity;

import java.util.Map;

/**
 * 统一错误响应：只回传可区分原因码与安全文案，保证：
 * <ul>
 *   <li>异常输入返回 4xx 而不是 500，服务持续可用；</li>
 *   <li>“未知版本 / 已吊销 / 完整性失败 / 引用残留 / 并发轮换”各自原因码不同；</li>
 *   <li>响应体绝不携带明文或密钥材料。</li>
 * </ul>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(KeyLifecycleException.class)
    public ResponseEntity<Map<String, Object>> handle(KeyLifecycleException ex) {
        HttpStatus status = switch (ex.getReason()) {
            case UNKNOWN_VERSION -> HttpStatus.NOT_FOUND;
            case REFERENCES_REMAIN, CONCURRENT_ROTATION -> HttpStatus.CONFLICT;
            default -> HttpStatus.BAD_REQUEST;
        };
        return ResponseEntity.status(status).body(body(ex.getReason(), safeMessage(ex.getMessage())));
    }

    /** 请求体 JSON 非法等：归入 INVALID_INPUT，避免 500。 */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(body(FailureReason.INVALID_INPUT, "malformed request body"));
    }

    private static Map<String, Object> body(FailureReason reason, String message) {
        return Map.of("reason", reason.name(), "message", message);
    }

    private static String safeMessage(String message) {
        // 最后一道防线：错误文案不允许携带换行等注入字符
        if (message == null || message.isBlank()) {
            return "request rejected";
        }
        return message.replace('\n', ' ').replace('\r', ' ');
    }
}
