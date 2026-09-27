package com.github.lisama569.cryptokeylifecyclejava.config;

import com.github.lisama569.cryptokeylifecyclejava.crypto.AesGcmCipher;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.InMemoryKeyStore;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyStore;
import com.github.lisama569.cryptokeylifecyclejava.migration.DataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.InMemoryDataRepository;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 本地密钥生命周期能力的 Spring 装配。
 *
 * <p>全部组件均为进程内本地实现，不依赖外部服务、真实凭据或网络资源。
 * 存储为内存实现；密钥材料仅存在于本 JVM 内。
 */
@Configuration
@EnableConfigurationProperties(KeyLifecycleProperties.class)
public class KeyLifecycleConfig {

    private static final Logger log = LoggerFactory.getLogger(KeyLifecycleConfig.class);

    @Bean
    public KeyStore keyStore() {
        return new InMemoryKeyStore();
    }

    @Bean
    public DataRepository dataRepository() {
        return new InMemoryDataRepository();
    }

    @Bean
    public AesGcmCipher aesGcmCipher(KeyLifecycleProperties props) {
        return new AesGcmCipher(props.getGcmIvBytes(), props.getGcmTagBits());
    }

    @Bean
    public CipherCodec cipherCodec() {
        return new CipherCodec();
    }

    @Bean
    public KeyManager keyManager(KeyStore keyStore, AesGcmCipher cipher, CipherCodec codec,
                                 KeyLifecycleProperties props) {
        KeyManager keyManager = new KeyManager(keyStore, cipher, codec, props.getAesKeyBits());
        // 启动即具备可用的当前版本；失败不吞异常，使部署问题显式暴露
        keyManager.generateAndActivate();
        log.info("keylifecycle initialized with first active version; aesKeyBits={}, gcmIvBytes={}, gcmTagBits={}, migrationBatchSize={}",
                props.getAesKeyBits(), props.getGcmIvBytes(), props.getGcmTagBits(),
                props.getMigrationBatchSize());
        return keyManager;
    }

    @Bean
    public MigrationService migrationService(KeyManager keyManager, DataRepository repository) {
        return new MigrationService(keyManager, repository);
    }

    @Bean
    public com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionLifecycleService versionLifecycleService(
            KeyManager keyManager, DataRepository repository) {
        return new com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionLifecycleService(
                keyManager, repository);
    }
}
