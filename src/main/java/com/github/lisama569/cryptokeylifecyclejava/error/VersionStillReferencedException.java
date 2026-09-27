package com.github.lisama569.cryptokeylifecyclejava.error;

/** 目标版本仍被历史数据引用（引用数未清零），拒绝下线。 */
public class VersionStillReferencedException extends KeyLifecycleException {
    public VersionStillReferencedException(String message) { super(message); }
    @Override public String reasonCode() { return "VERSION_STILL_REFERENCED"; }
}
