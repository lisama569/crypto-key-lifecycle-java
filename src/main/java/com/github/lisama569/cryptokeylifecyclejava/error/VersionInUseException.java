package com.github.lisama569.cryptokeylifecyclejava.error;

/** 目标密钥版本仍被数据记录引用，安全下线被拒绝。 */
public class VersionInUseException extends KeyLifecycleException {
    public VersionInUseException(String message) { super(message); }
    @Override public String reasonCode() { return "VERSION_STILL_REFERENCED"; }
}
