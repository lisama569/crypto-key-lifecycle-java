package com.github.lisama569.cryptokeylifecyclejava.error;

/**
 * 密钥生命周期相关异常的统一基类。
 * 子类异常消息中禁止出现明文或密钥材料。
 */
public class KeyLifecycleException extends RuntimeException {

    private final FailureReason reason;

    public KeyLifecycleException(FailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public KeyLifecycleException(FailureReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public FailureReason getReason() {
        return reason;
    }
}
