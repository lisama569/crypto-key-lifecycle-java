package com.github.lisama569.cryptokeylifecyclejava.error;

/** 请求的密钥版本不存在（未知版本）。 */
public class UnknownVersionException extends KeyLifecycleException {
    public UnknownVersionException(String message) { super(message); }
    @Override public String reasonCode() { return "UNKNOWN_VERSION"; }
}
