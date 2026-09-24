package com.github.lisama569.cryptokeylifecyclejava.error;

public class InvalidInputException extends KeyLifecycleException {
    public InvalidInputException(String message) {
        super(FailureReason.INVALID_INPUT, message);
    }
}
