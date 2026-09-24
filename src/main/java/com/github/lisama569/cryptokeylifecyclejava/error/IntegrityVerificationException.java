package com.github.lisama569.cryptokeylifecyclejava.error;

/** 密文完整性校验失败（数据被篡改或认证标签不匹配）。 */
public class IntegrityVerificationException extends KeyLifecycleException {
    public IntegrityVerificationException(String message) { super(message); }
    public IntegrityVerificationException(String message, Throwable cause) { super(message, cause); }
    @Override public String reasonCode() { return "INTEGRITY_FAILURE"; }
}
