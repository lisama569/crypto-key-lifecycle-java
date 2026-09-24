package com.github.lisama569.cryptokeylifecyclejava.error;

/** 状态冲突：重复启用同一版本、并发轮换冲突等。 */
public class KeyConflictException extends KeyLifecycleException {
    public KeyConflictException(String message) { super(message); }
    @Override public String reasonCode() { return "KEY_STATE_CONFLICT"; }
}
