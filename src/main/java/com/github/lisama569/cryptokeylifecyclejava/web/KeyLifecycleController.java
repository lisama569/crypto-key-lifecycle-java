package com.github.lisama569.cryptokeylifecyclejava.web;

import com.github.lisama569.cryptokeylifecyclejava.config.KeyLifecycleProperties;
import com.github.lisama569.cryptokeylifecyclejava.crypto.CipherCodec;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyManager;
import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionDecommissionService;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceReport;
import com.github.lisama569.cryptokeylifecyclejava.decommission.VersionReferenceService;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationProgress;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationService;
import com.github.lisama569.cryptokeylifecyclejava.migration.TargetedMigrationProgress;
import com.github.lisama569.cryptokeylifecyclejava.web.dto.Dtos;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
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
    private final VersionReferenceService versionReferenceService;
    private final VersionDecommissionService versionDecommissionService;
    private final CipherCodec cipherCodec;
    private final KeyLifecycleProperties properties;

    public KeyLifecycleController(KeyManager keyManager, MigrationService migrationService,
                                  VersionReferenceService versionReferenceService,
                                  VersionDecommissionService versionDecommissionService,
                                  CipherCodec cipherCodec, KeyLifecycleProperties properties) {
        this.keyManager = keyManager;
        this.migrationService = migrationService;
        this.versionReferenceService = versionReferenceService;
        this.versionDecommissionService = versionDecommissionService;
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
     * 传 0 或负数表示一次性迁移全部。
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

    /** 按来源版本定向清理一批数据，只处理该旧版本加密的记录。 */
    @PostMapping("/migrate/version")
    public TargetedMigrationProgress migrateVersion(@RequestParam int version,
                                                    @RequestParam(required = false) Integer limit) {
        Integer effectiveLimit = limit != null ? limit : properties.getMigrationBatchSize();
        return migrationService.migrateVersion(version, effectiveLimit);
    }

    /** 查看某版本的实时引用统计与安全下线预检结论。 */
    @GetMapping("/versions/{version}/references")
    public VersionReferenceReport references(@org.springframework.web.bind.annotation.PathVariable int version) {
        return versionReferenceService.inspect(version);
    }

    /** 安全下线预检（只判定，不改动任何状态）。 */
    @PostMapping("/decommission/preflight")
    public VersionReferenceReport decommissionPreflight(
            @RequestBody(required = false) Dtos.DecommissionRequest request) {
        if (request == null || request.version() == null) {
            throw new InvalidInputException("field 'version' is required");
        }
        return versionDecommissionService.preflight(request.version());
    }

    /** 执行安全下线：仅当引用清零且非当前服务版本时成功。 */
    @PostMapping("/decommission")
    public Dtos.VersionView decommission(
            @RequestBody(required = false) Dtos.DecommissionRequest request) {
        if (request == null || request.version() == null) {
            throw new InvalidInputException("field 'version' is required");
        }
        return toView(versionDecommissionService.decommission(request.version()));
    }

    private static Dtos.VersionView toView(KeyVersion v) {
        return new Dtos.VersionView(v.version(), v.state().name(),
                v.createdAt() == null ? null : v.createdAt().toString(),
                v.retiredAt() == null ? null : v.retiredAt().toString(),
                v.revokedAt() == null ? null : v.revokedAt().toString(),
                v.decommissionedAt() == null ? null : v.decommissionedAt().toString());
    }
}
