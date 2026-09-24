package com.github.lisama569.cryptokeylifecyclejava.error;

/** 目标密钥版本已被吊销，拒绝操作。 */
public class RevokedVersionException extends KeyLifecycleException {
    public RevokedVersionException(String message) { super(message); }
    @Override public String reasonCode() { return "REVOKED_VERSION"; }
}
