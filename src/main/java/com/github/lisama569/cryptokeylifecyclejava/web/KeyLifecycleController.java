package com.github.lisama569.cryptokeylifecyclejava.web;

import com.github.lisama569.cryptokeylifecyclejava.config.KeyLifecycleProperties;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionLifecycleService;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.VersionReferenceStats;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationProgress;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.SourceCleanupProgress;
import com.github.lisama569.cryptokeylifecyclejava.web.dto.Dtos;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 密钥生命周期与数据迁移的本地 REST 接口。
 *
 * <p>所有失败经 {@link LifecycleExceptionHandler} 转换为 {@code {error, message}}，
 * 不回显明文。
 */
@RestController
@RequestMapping("/api/keys")
public class KeyLifecycleController {

    private final KeyManager keyManager;
    private final MigrationService migrationService;
    private final VersionLifecycleService versionLifecycleService;
    private final CipherCodec cipherCodec;
    private final KeyLifecycleProperties properties;

    public KeyLifecycleController(KeyManager keyManager, MigrationService migrationService,
                                  VersionLifecycleService versionLifecycleService,
                                  CipherCodec cipherCodec, KeyLifecycleProperties properties) {
        this.keyManager = keyManager;
        this.migrationService = migrationService;
        this.versionLifecycleService = versionLifecycleService;
        this.cipherCodec = cipherCodec;
        this.properties = properties;
    }

    /** 原子轮换：旧 ACTIVE 转 RETIRED，新密钥成为 ACTIVE。 */
    @PostMapping("/rotate")
    public Dtos.RotateResponse rotate() {
        KeyManager.RotationResult result = keyManager.rotate();
        return new Dtos.RotateResponse(result.previousVersion(), result.active().version());
    }

    /** 吊销指定版本（建议先完成该版本的数据迁移）。 */
    @PostMapping("/revoke")
    public Dtos.VersionView revoke(@RequestBody(required = false) Dtos.RevokeRequest request) {
        if (request == null || request.version() == null) {
            throw new InvalidInputException("field 'version' is required");
        }
        return toView(keyManager.revoke(request.version()));
    }

    @GetMapping("/versions")
    public List<Dtos.VersionView> versions() {
        return keyManager.listVersions().stream()
                .map(KeyLifecycleController::toView)
                .toList();
    }

    @PostMapping("/encrypt")
    public Dtos.EncryptResponse encrypt(@RequestBody(required = false) Dtos.EncryptRequest request) {
        if (request == null) {
            throw new InvalidInputException("request body is required");
        }
        String ciphertext = keyManager.encrypt(request.plaintext());
        int version = keyManager.currentVersion().version();
        return new Dtos.EncryptResponse(ciphertext, version);
    }

    @PostMapping("/decrypt")
    public Dtos.DecryptResponse decrypt(@RequestBody(required = false) Dtos.DecryptRequest request) {
        if (request == null || request.ciphertext() == null) {
            throw new InvalidInputException("field 'ciphertext' is required");
        }
        int version = cipherCodec.decode(request.ciphertext()).keyVersion();
        String plaintext = keyManager.decrypt(request.ciphertext());
        return new Dtos.DecryptResponse(plaintext, version);
    }

    /**
     * 执行一批迁移。未传 limit 时使用 {@code keylifecycle.migration-batch-size}；
     * 传 0 或负数表示一次性迁移全部。传 fromVersion 时只定向清理该来源版本的数据。
     */
    @PostMapping("/migrate")
    public MigrationProgress migrate(@RequestParam(required = false) Integer limit) {
        Integer effectiveLimit = limit != null ? limit : properties.getMigrationBatchSize();
        return migrationService.migrateToCurrent(effectiveLimit);
    }

    @GetMapping("/migrate/progress")
    public MigrationProgress progress() {
        return migrationService.progress();
    }

    /**
     * 按来源版本定向清理一批数据：只处理仍停留在 fromVersion 的记录，
     * 分批/中断续跑/幂等语义与全量迁移一致。
     */
    @PostMapping("/migrate/from/{fromVersion}")
    public SourceCleanupProgress migrateFrom(@PathVariable int fromVersion,
                                             @RequestParam(required = false) Integer limit) {
        Integer effectiveLimit = limit != null ? limit : properties.getMigrationBatchSize();
        return migrationService.migrateFromVersion(fromVersion, effectiveLimit);
    }

    /** 全部版本的引用统计与安全下线预检结论（同一份数据快照，互相一致）。 */
    @GetMapping("/references")
    public List<VersionReferenceStats> references() {
        return versionLifecycleService.stats();
    }

    /** 单个版本的引用统计与下线预检结论；未知版本返回 404。 */
    @GetMapping("/versions/{version}/references")
    public VersionReferenceStats referencesFor(@PathVariable int version) {
        return versionLifecycleService.statsFor(version);
    }

    /**
     * 受保护的安全下线：仅当引用清零且该版本不是当前 ACTIVE 时进入 REVOKED 终态。
     * 仍在提供服务（VERSION_IS_ACTIVE）或仍被数据依赖（VERSION_STILL_REFERENCED）时拒绝；
     * 重复提交/并发落败得到一致的 REVOKED_VERSION。
     */
    @PostMapping("/decommission")
    public Dtos.VersionView decommission(@RequestBody(required = false) Dtos.DecommissionRequest request) {
        if (request == null || request.version() == null) {
            throw new InvalidInputException("field 'version' is required");
        }
        return toView(versionLifecycleService.decommission(request.version()));
    }

    private static Dtos.VersionView toView(KeyVersion v) {
        return new Dtos.VersionView(v.version(), v.state().name(),
                v.createdAt() == null ? null : v.createdAt().toString(),
                v.retiredAt() == null ? null : v.retiredAt().toString(),
                v.revokedAt() == null ? null : v.revokedAt().toString());
    }
}
