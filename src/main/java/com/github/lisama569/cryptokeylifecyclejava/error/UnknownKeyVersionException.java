package com.github.lisama569.cryptokeylifecyclejava.error;

public class UnknownKeyVersionException extends KeyLifecycleException {
    public UnknownKeyVersionException(String message) {
        super(FailureReason.UNKNOWN_VERSION, message);
    }
}
