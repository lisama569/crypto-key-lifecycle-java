package com.github.lisama569.cryptokeylifecyclejava.error;

/** 目标版本已安全下线（DECOMMISSIONED 终态），拒绝重复下线或加解密。 */
public class VersionDecommissionedException extends KeyLifecycleException {
    public VersionDecommissionedException(String message) { super(message); }
    @Override public String reasonCode() { return "VERSION_DECOMMISSIONED"; }
}
