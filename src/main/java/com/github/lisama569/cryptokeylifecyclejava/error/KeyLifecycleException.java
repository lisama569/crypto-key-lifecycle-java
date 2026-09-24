package com.github.lisama569.cryptokeylifecyclejava.error;

/** 密钥生命周期相关异常的统一基类，按失败原因区分子类型。 */
public abstract class KeyLifecycleException extends RuntimeException {
    protected KeyLifecycleException(String message) { super(message); }
    protected KeyLifecycleException(String message, Throwable cause) { super(message, cause); }
    public abstract String reasonCode();
}
