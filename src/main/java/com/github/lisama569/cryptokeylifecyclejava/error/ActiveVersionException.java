package com.github.lisama569.cryptokeylifecyclejava.error;

/** 目标密钥版本是当前正在提供服务的 ACTIVE 版本，安全下线被拒绝。 */
public class ActiveVersionException extends KeyLifecycleException {
    public ActiveVersionException(String message) { super(message); }
    @Override public String reasonCode() { return "VERSION_IS_ACTIVE"; }
}
