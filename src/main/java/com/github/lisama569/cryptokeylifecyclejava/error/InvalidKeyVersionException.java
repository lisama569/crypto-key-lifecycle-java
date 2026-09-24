package com.github.lisama569.cryptokeylifecyclejava.error;

/** 版本状态非法或重复启用；并发轮换被拒绝时也使用该异常。 */
public class InvalidKeyVersionException extends KeyLifecycleException {
    public InvalidKeyVersionException(FailureReason reason, String message) {
        super(reason, message);
    }
}
