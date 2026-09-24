package com.github.lisama569.cryptokeylifecyclejava.error;

public class IntegrityVerificationException extends KeyLifecycleException {
    public IntegrityVerificationException(String message) {
        super(FailureReason.INTEGRITY_FAILURE, message);
    }

    public IntegrityVerificationException(String message, Throwable cause) {
        super(FailureReason.INTEGRITY_FAILURE, message, cause);
    }
}
