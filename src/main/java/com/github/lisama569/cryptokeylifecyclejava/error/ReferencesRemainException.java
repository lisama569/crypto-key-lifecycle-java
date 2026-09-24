package com.github.lisama569.cryptokeylifecyclejava.error;

public class ReferencesRemainException extends KeyLifecycleException {
    public ReferencesRemainException(String message) {
        super(FailureReason.REFERENCES_REMAIN, message);
    }
}
