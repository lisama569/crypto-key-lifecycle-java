package com.github.lisama569.cryptokeylifecyclejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** 密钥生命周期关键配置项（前缀 keylifecycle）。 */
@ConfigurationProperties(prefix = "keylifecycle")
public class KeyLifecycleProperties {
    private int aesKeyBits = 256;
    private int gcmIvBytes = 12;
    private int gcmTagBits = 128;
    private int migrationBatchSize = 100;
    public int getAesKeyBits() { return aesKeyBits; }
    public void setAesKeyBits(int v) { this.aesKeyBits = v; }
    public int getGcmIvBytes() { return gcmIvBytes; }
    public void setGcmIvBytes(int v) { this.gcmIvBytes = v; }
    public int getGcmTagBits() { return gcmTagBits; }
    public void setGcmTagBits(int v) { this.gcmTagBits = v; }
    public int getMigrationBatchSize() { return migrationBatchSize; }
    public void setMigrationBatchSize(int v) { this.migrationBatchSize = v; }
}
