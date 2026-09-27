package com.github.lisama569.cryptokeylifecyclejava.error;

/** 目标版本是当前正在提供服务的 ACTIVE 版本，拒绝下线。 */
public class VersionActiveException extends KeyLifecycleException {
    public VersionActiveException(String message) { super(message); }
    @Override public String reasonCode() { return "VERSION_ACTIVE"; }
}
