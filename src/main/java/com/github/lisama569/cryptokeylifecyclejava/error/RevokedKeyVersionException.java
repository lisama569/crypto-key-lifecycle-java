package com.github.lisama569.cryptokeylifecyclejava.error;

public class RevokedKeyVersionException extends KeyLifecycleException {
    public RevokedKeyVersionException(String message) {
        super(FailureReason.REVOKED_VERSION, message);
    }
}
