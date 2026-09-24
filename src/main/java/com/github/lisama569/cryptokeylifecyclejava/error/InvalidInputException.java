package com.github.lisama569.cryptokeylifecyclejava.error;

/** 异常输入：null、空明文、非法密文格式等。 */
public class InvalidInputException extends KeyLifecycleException {
    public InvalidInputException(String message) { super(message); }
    @Override public String reasonCode() { return "INVALID_INPUT"; }
}
