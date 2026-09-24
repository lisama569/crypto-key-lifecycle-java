package com.github.lisama569.cryptokeylifecyclejava.migration;

/** 被托管的业务数据记录。status 取 {@link RecordStatus} 中的常量值。 */
public record DataRecord(String id, String ciphertext, int keyVersion, String status) {
}
