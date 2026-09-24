package com.github.lisama569.cryptokeylifecyclejava.error;

public class MigrationException extends KeyLifecycleException {
    public MigrationException(FailureReason reason, String message) {
        super(reason, message);
    }
}
