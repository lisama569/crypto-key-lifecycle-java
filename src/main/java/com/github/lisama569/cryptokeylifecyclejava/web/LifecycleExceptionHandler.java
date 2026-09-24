package com.github.lisama569.cryptokeylifecyclejava.web;

import com.github.lisama569.cryptokeylifecyclejava.error.IntegrityVerificationException;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyConflictException;
import com.github.lisama569.cryptokeylifecyclejava.error.KeyLifecycleException;
import com.github.lisama569.cryptokeylifecyclejava.error.RevokedVersionException;
import com.github.lisama569.cryptokeylifecyclejava.error.UnknownVersionException;
import com.github.lisama569.cryptokeylifecyclejava.web.dto.Dtos;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 将可区分的失败原因映射为不同 HTTP 状态码：
 * <ul>
 *   <li>INVALID_INPUT / 不可读请求体 → 400</li>
 *   <li>UNKNOWN_VERSION → 404</li>
 *   <li>REVOKED_VERSION / INTEGRITY_FAILURE / KEY_STATE_CONFLICT → 409</li>
 * </ul>
 * 错误响应仅包含机器可读的原因码与不含明文的描述。
 */
@RestControllerAdvice
public class LifecycleExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(LifecycleExceptionHandler.class);

    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<Dtos.ErrorResponse> handleInvalidInput(InvalidInputException ex) {
        return build(HttpStatus.BAD_REQUEST, ex);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Dtos.ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        log.warn("op=HTTP result=REJECT basis=MALFORMED_BODY");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new Dtos.ErrorResponse("INVALID_INPUT", "request body is missing or malformed"));
    }

    @ExceptionHandler(UnknownVersionException.class)
    public ResponseEntity<Dtos.ErrorResponse> handleUnknownVersion(UnknownVersionException ex) {
        return build(HttpStatus.NOT_FOUND, ex);
    }

    @ExceptionHandler(RevokedVersionException.class)
    public ResponseEntity<Dtos.ErrorResponse> handleRevoked(RevokedVersionException ex) {
        return build(HttpStatus.CONFLICT, ex);
    }

    @ExceptionHandler(IntegrityVerificationException.class)
    public ResponseEntity<Dtos.ErrorResponse> handleIntegrity(IntegrityVerificationException ex) {
        return build(HttpStatus.CONFLICT, ex);
    }

    @ExceptionHandler(KeyConflictException.class)
    public ResponseEntity<Dtos.ErrorResponse> handleConflict(KeyConflictException ex) {
        return build(HttpStatus.CONFLICT, ex);
    }

    /** 兜底：任何未预期异常返回 500 且不含内部细节，避免泄露明文或堆栈。 */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Dtos.ErrorResponse> handleUnexpected(Exception ex) {
        log.error("op=HTTP result=ERROR basis=UNEXPECTED type={}", ex.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new Dtos.ErrorResponse("INTERNAL_ERROR", "request failed due to an internal error"));
    }

    private ResponseEntity<Dtos.ErrorResponse> build(HttpStatus status, KeyLifecycleException ex) {
        log.warn("op=HTTP result=REJECT basis={} status={}", ex.reasonCode(), status.value());
        return ResponseEntity.status(status)
                .body(new Dtos.ErrorResponse(ex.reasonCode(), ex.getMessage()));
    }
}
