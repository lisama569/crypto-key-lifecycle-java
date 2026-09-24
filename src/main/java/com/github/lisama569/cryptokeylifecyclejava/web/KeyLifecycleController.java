package com.github.lisama569.cryptokeylifecyclejava.web;

import com.github.lisama569.cryptokeylifecyclejava.crypto.KeyVersion;
import com.github.lisama569.cryptokeylifecyclejava.error.InvalidInputException;
import com.github.lisama569.cryptokeylifecyclejava.lifecycle.KeyVersionInfo;
import com.github.lisama569.cryptokeylifecyclejava.migration.MigrationProgress;
import com.github.lisama569.cryptokeylifecyclejava.service.CryptoService;
import com.github.lisama569.cryptokeylifecyclejava.service.KeyAdminService;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 管理/数据面 REST 接口。错误响应统一由 {@link GlobalExceptionHandler} 输出
 * {reason,message}，message 中不含明文与密钥材料。
 */
@RestController
@RequestMapping("/api")
public class KeyLifecycleController {

    private final CryptoService cryptoService;
    private final KeyAdminService keyAdminService;

    public KeyLifecycleController(CryptoService cryptoService, KeyAdminService keyAdminService) {
        this.cryptoService = cryptoService;
        this.keyAdminService = keyAdminService;
    }

    /** 写入并加密一条数据。body: {"plaintext": "..."}；响应不含明文。 */
    @PostMapping("/data/{id}")
    public Map<String, Object> encrypt(@PathVariable String id, @RequestBody(required = false) Map<String, String> body) {
        if (body == null || !body.containsKey("plaintext")) {
            throw new InvalidInputException("field 'plaintext' is required");
        }
        var record = cryptoService.encrypt(id, body.get("plaintext"));
        return Map.of("id", record.getId(), "keyVersion", record.getKeyVersion());
    }

    /** 解密读取一条数据。 */
    @GetMapping("/data/{id}")
    public Map<String, Object> decrypt(@PathVariable String id) {
        String plaintext = cryptoService.decrypt(id);
        return Map.of("id", id, "plaintext", plaintext);
    }

    /** 原子轮换到新密钥版本。 */
    @PostMapping("/keys/rotate")
    public Map<String, Object> rotate() {
        KeyVersion key = keyAdminService.rotate();
        return Map.of("keyVersion", key.getVersion(), "state", key.getState().name());
    }

    @GetMapping("/keys")
    public List<KeyVersionInfo> listKeys() {
        return keyAdminService.versions();
    }

    /** 吊销版本；仍有数据引用时返回 409 REFERENCES_REMAIN。 */
    @PostMapping("/keys/{version}/revoke")
    public Map<String, Object> revoke(@PathVariable int version) {
        keyAdminService.revoke(version);
        return Map.of("keyVersion", version, "state", "REVOKED");
    }

    /**
     * 启动/续跑迁移。body:
     * {"fromVersion":1,"batchSize":50,"maxBatches":10,"migrationId":"mig-xxx"}
     * migrationId 缺省表示新建。
     */
    @PostMapping("/migrations")
    public MigrationProgress startMigration(@RequestBody(required = false) Map<String, Object> body) {
        if (body == null || body.get("fromVersion") == null) {
            throw new InvalidInputException("field 'fromVersion' is required");
        }
        int fromVersion = asInt(body.get("fromVersion"), "fromVersion");
        Integer batchSize = body.get("batchSize") == null ? null : asInt(body.get("batchSize"), "batchSize");
        Integer maxBatches = body.get("maxBatches") == null ? null : asInt(body.get("maxBatches"), "maxBatches");
        Object resume = body.get("migrationId");
        String resumeId = resume == null ? null : String.valueOf(resume);
        return keyAdminService.migrate(fromVersion, batchSize, maxBatches, resumeId);
    }

    @GetMapping("/migrations/{migrationId}")
    public MigrationProgress migrationProgress(@PathVariable String migrationId) {
        return keyAdminService.migrationProgress(migrationId);
    }

    /** 请求中断某次迁移（安全暂停，可续跑）。 */
    @PostMapping("/migrations/{migrationId}/interrupt")
    public Map<String, Object> interrupt(@PathVariable String migrationId) {
        keyAdminService.interruptMigration(migrationId);
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("migrationId", migrationId);
        resp.put("interruptRequested", true);
        return resp;
    }

    private static int asInt(Object value, String field) {
        if (value instanceof Number number) {
            int v = number.intValue();
            if (v < 0) {
                throw new InvalidInputException(field + " must not be negative");
            }
            return v;
        }
        throw new InvalidInputException(field + " must be a number");
    }
}
