package com.github.lisama569.cryptokeylifecyclejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 密钥生命周期配置项（前缀 keylifecycle）：
 * <ul>
 *   <li>keySizeBits: 密钥位长度，默认 256；</li>
 *   <li>gcmIvLengthBytes / gcmTagLengthBits: GCM IV 与认证标签长度；</li>
 *   <li>migrationBatchSize: 迁移默认每批记录数；</li>
 *   <li>bootstrapKeyOnStartup: 启动时是否自动生成并启用第一个版本。</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "keylifecycle")
public class KeyLifecycleProperties {

    private int keySizeBits = 256;
    private int gcmIvLengthBytes = 12;
    private int gcmTagLengthBits = 128;
    private int migrationBatchSize = 100;
    private boolean bootstrapKeyOnStartup = true;

    public int getKeySizeBits() {
        return keySizeBits;
    }

    public void setKeySizeBits(int keySizeBits) {
        this.keySizeBits = keySizeBits;
    }

    public int getGcmIvLengthBytes() {
        return gcmIvLengthBytes;
    }

    public void setGcmIvLengthBytes(int gcmIvLengthBytes) {
        this.gcmIvLengthBytes = gcmIvLengthBytes;
    }

    public int getGcmTagLengthBits() {
        return gcmTagLengthBits;
    }

    public void setGcmTagLengthBits(int gcmTagLengthBits) {
        this.gcmTagLengthBits = gcmTagLengthBits;
    }

    public int getMigrationBatchSize() {
        return migrationBatchSize;
    }

    public void setMigrationBatchSize(int migrationBatchSize) {
        this.migrationBatchSize = migrationBatchSize;
    }

    public boolean isBootstrapKeyOnStartup() {
        return bootstrapKeyOnStartup;
    }

    public void setBootstrapKeyOnStartup(boolean bootstrapKeyOnStartup) {
        this.bootstrapKeyOnStartup = bootstrapKeyOnStartup;
    }
}
