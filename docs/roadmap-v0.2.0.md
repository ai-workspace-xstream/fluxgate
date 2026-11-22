# Fluxgate v0.2.0 架构与特性规划

> **状态**：已确认规划（Planning Approved）  
> **基准版本**：`v0.1.0` (`142ca088efc8da218b7cb3ddec0e57ee2892e04a`)  
> **目标版本**：`v0.2.0`

---

## 1. 目标与非功能约束

Fluxgate 面向 **1 vCPU / 1 GiB 内存边缘节点**设计，在 `v0.1.0` 基于 **Rust + Cloudflare Pingora (`0.9.1`)** 跑通 Caddyfile DSL、UDS `h2c` 流式代理、499 降噪与 Prometheus `/metrics` 的基础上，`v0.2.0` 重点补齐**密钥安全、GitOps 声明式配置、Ansible Pull 自收敛与自动 DNS-01 证书管理**四大核心能力。

### 核心设计原则与约束

1. **保持单二进制极简形态**
   - 所有后台同步与续期逻辑均运行在 Pingora `BackgroundService` 与同一 Tokio Runtime 中，不引入外部守护进程（如 `vault-agent`、`certbot`、`lego`）。
   - 不内置 Git 运行时（`libgit2` / `git` 子进程），保持空载常驻内存（RSS）目标 **`< 10 MiB`**，避免依赖膨胀与攻击面扩大。
2. **三平面严格解耦**
   - **Secret 平面（Vault KV v2）**：密钥与证书私钥仅驻留内存，严禁入 Git、严禁明文落盘（TLS 本地缓存除外，需 `0700`/`0600` 严格权限）、严禁打印日志或报错堆栈。
   - **声明平面（GitOps）**：仅存放非敏感路由规则、域名列表、Vault 路径指针与 ACME 策略，接受静态安全门禁检查。
   - **收敛平面（Ansible Pull）**：负责节点级二进制升级（校验 `SHA256SUMS`）、GitOps 声明同步、配置预检与无损 `reload`。
3. **100% 向后兼容 `v0.1.0`**
   - 保留现有静态配置语法（如 `tls /path/cert /path/key`、纯文件 `import` 等），未启用 Vault / ACME 时不额外发起任何外部网络请求。

### 总体架构

```
GitOps Repo (非敏感声明) ──► Ansible Pull ──► /var/lib/ansible-pull/gitops ──► Fluxgatefile (import)
                                                                                     │
Vault KV v2 (Secret 平面) ──► VaultSyncService ──► SecretStore (内存/zeroize) ────────┼──► Fluxgate (Pingora)
                                                        ▲                            │       ├── ArcSwap 路由热重载
ACME CA (LE) + DNS API (CF/Ali) ◄── CertRenewalService ─┴── (KV v2 CAS 多节点共享) ──┘       └── DynamicCertStore (SNI 热替换)
```

---

## 2. 特性详细设计

### 特性 1：Vault 集成（Sync KV Path 安全加载 Secret Key）

**目标**：在不将任何 API Token、私钥或共享密钥写入 Git 或配置文件的前提下，安全、动态地同步 Vault KV v2 密钥到内存。

#### 2.1 DSL 声明规范

在全局块新增 `vault { ... }` 配置块，复用现有 `kv/data/...` 路径规范：

```caddy
{
    vault {
        addr env(VAULT_ADDR)
        namespace env(VAULT_NAMESPACE)          # 可选
        auth approle                            # 支持 approle（推荐）| token
        sync dns kv/data/prod/fluxgate/dns-tokens 5m
        sync tls kv/data/prod/fluxgate/tls 10m
    }
}
```

- **引用语法**：配置中通过 `{vault.<alias>.<key>}`（例如 `{vault.dns.cf_api_token}`、`{vault.dns.alidns_access_key_id}`）引用同步的密钥字段。
- **离线校验**：`fluxgate validate --offline`（以及默认 `validate`）仅校验 `{vault.<alias>.<key>}` 占位符格式与 `<alias>` 是否在 `vault.sync` 中声明，不强制要求构建机或 CI 环境能连通线上 Vault。

#### 2.2 认证、同步与安全机制

1. **认证模式**
   - **AppRole（推荐用于无人值守边缘节点）**：读取 `VAULT_ROLE_ID` / `VAULT_SECRET_ID`（或 systemd `LoadCredential` 注入的凭据文件），登录后自动追踪 TTL 并在过期前续期或重签。
   - **Token 模式**：读取 `VAULT_TOKEN`，在后台定期执行 `/v1/auth/token/renew-self`（如可续期）。
   - 严格校验 Vault HTTPS TLS 证书（支持系统 CA 与可选自定义 CA 路径）。
2. **增量变更检测与热生效**
   - 调用 Vault KV v2 API `/v1/<mount>/data/<path>`，对比响应中的 `data.metadata.version`；仅当版本号递增时更新内存 `SecretStore`，并通知下游依赖方（如 DNS Provider 或证书缓存）。
3. **内存安全与日志脱敏**
   - 使用 `secrecy::SecretString` / `zeroize::Zeroize` 封装密钥，旧快照替换后立即清零内存。
   - 统一脱敏日志与错误输出，任何配置渲染、错误堆栈或监控标签中禁止出现 Secret 原文。
4. **容错与监控指标**
   - Vault 短暂不可达时保留最近一次有效内存快照，后台按指数退避重试，不影响现有流量转发。
   - 新增 Prometheus 指标：
     - `fluxgate_vault_sync_success{alias="..."}`（Gauge: `1`/`0`）
     - `fluxgate_vault_last_sync_timestamp_seconds{alias="..."}`（Gauge）
     - `fluxgate_vault_sync_version{alias="..."}`（Gauge: KV `metadata.version`）

---

### 特性 2：GitOps 非敏感信息集成（Ansible Pull + `import` 热重载）

**目标**：利用现有 `ansible-pull` 将 GitOps 仓库的节点声明拉取到本地，由 Fluxgate 通过 `import` 消费并支持无损热重载（Zero-Downtime Reload）。

#### 2.1 边界约定与目录组织

- **同步机制**：`v0.2.0` 采用 **Ansible Pull 拉取 GitOps + Fluxgate `import` 热重载**，不在 Fluxgate 内置 Git 客户端。
- GitOps 仓库中仅包含：站点域名、监听端口、Upstream 路由、rewrite/URI 清洗规则、Vault 路径指针（`kv/data/...`）、ACME 策略声明。
- 本地布局示例：
  ```caddy
  # /etc/fluxgate/Fluxgatefile
  {
      grace_period 15s
      metrics 127.0.0.1:9102
      vault {
          addr env(VAULT_ADDR)
          auth approle
          sync dns kv/data/prod/fluxgate/dns-tokens 5m
      }
  }

  import /var/lib/ansible-pull/gitops/nodes/jp-xconnect-02/*.conf
  ```

#### 2.2 零中断路由热重载

- 将 [src/proxy/service.rs](file:///Users/shenlan/workspaces/fluxgate/src/proxy/service.rs) 中强绑定的 `Arc<CompiledRouter>` 升级为 `Arc<ArcSwap<CompiledRouter>>`（或同等原子指针切换结构）。
- 收到 `SIGHUP` 或 `fluxgate reload` 指令后：
  1. 重新解析并执行 `validate_config`（含占位符引用合法性检查）。
  2. 若校验失败，记录错误日志、`fluxgate_config_reload_success 0`，**保持当前运行中路由与 TLS 配置完全不变**。
  3. 若校验成功，构建新的 `CompiledRouter`，原子替换路由指针并触发 `DynamicCertStore` 同步；已建立的长流式连接（H2/UDS）继续沿旧路由自然结束，新请求立即使用新路由。

#### 2.3 安全门禁与可观测性

- **敏感信息防泄漏校验**：新增 `fluxgate validate --strict-gitops`（或在 CI/Ansible 预检中启用），扫描配置文件与 `import` 目标中的疑似明文凭据（如 `-----BEGIN .* PRIVATE KEY-----`、疑似 Cloudflare/Aliyun/Vault 明文字面量 Token），一旦命中直接拒绝通过，强制引导改用 `{vault.<alias>.<key>}`。
- **Prometheus 指标**：
  - `fluxgate_config_reload_success`（Gauge: `1`/`0`）
  - `fluxgate_config_last_reload_timestamp_seconds`（Gauge）
  - `fluxgate_config_info{sha256="..."}`（Gauge: 当前生效配置摘要指纹）

---

### 特性 3：Ansible Pull Playbook 集成

**目标**：将 Fluxgate 融入 `ai-workspace-infra/playbooks` 既有的 `ansible-pull` 节点自收敛体系（对齐 `pull_gitops_declaration.yml`、`pull_observability_agent.yml`）。

#### 3.1 Fluxgate 仓库侧改造

- **新增 CLI 子命令**（[src/cli.rs](file:///Users/shenlan/workspaces/fluxgate/src/cli.rs)）：
  - `fluxgate reload`：向运行中的 Fluxgate 主进程发送 `SIGHUP`（依据 PID 文件或控制 Socket）并校验重载结果状态。
  - `fluxgate doctor`：一键输出配置有效性、Vault 连通与认证状态、本地/Vault 证书剩余有效期、端口监听与文件权限健康报告。
- **Systemd Unit 增强**（[deploy/fluxgate.service](file:///Users/shenlan/workspaces/fluxgate/deploy/fluxgate.service)）：
  - 补充 `ExecReload=/usr/local/bin/fluxgate reload`
  - 支持 `EnvironmentFile=-/etc/fluxgate/fluxgate.env` 与可选 `LoadCredential`（注入 Vault AppRole 凭据，无需环境变量明文暴露）。

#### 3.2 `ai-workspace-infra/playbooks` 侧集成

- **新增 `pull_fluxgate.yml`**：支持节点本机执行：
  ```bash
  ansible-pull -U https://github.com/ai-workspace-infra/playbooks.git \
    -d /var/lib/ansible-pull/playbooks-fluxgate -i localhost, pull_fluxgate.yml
  ```
  读取 `/etc/ansible-pull/gitops-declaration.env` 与 `/var/lib/ansible-pull/gitops`，完成本地声明拉取与配置渲染。
- **增强 `roles/vhosts/fluxgate`**：
  - 按目标主机 `ansible_architecture`（`x86_64` -> `linux-amd64`，`aarch64` -> `linux-arm64`）自动拉取对应 GitHub Release 二进制，并**强制校验 `SHA256SUMS`** 后替换 `/usr/local/bin/fluxgate`。
  - 注册 `ansible-pull-fluxgate.service` 与 `ansible-pull-fluxgate.timer`（配置 `RandomizedDelaySec` 随机抖动防止上游并发风暴）。
  - 变更收敛策略：**仅配置变更执行 `fluxgate validate && systemctl reload fluxgate`，仅二进制版本升级时执行 `systemctl restart fluxgate`**。

---

### 特性 4：自动续期 DNS-01 证书（类似 Caddy）+ Vault KV 多节点共享

**目标**：提供纯 Rust、零外部工具依赖的 Caddy 风格自动化 TLS，并通过 **Vault KV v2 多节点证书共享**解决多台边缘节点同域名/泛域名签发触发 Let's Encrypt 限流的问题。

#### 4.1 Caddy 风格 DSL

在完全兼容静态 `tls <cert> <key>` 的同时，支持块级声明：

```caddy
*.svc.plus jp-xconnect-02.svc.plus {
    tls {
        issuer acme {
            email ops@svc.plus
            ca letsencrypt                  # 支持 letsencrypt | letsencrypt-staging | 自定义 ACME Directory URL
        }
        dns cloudflare {vault.dns.cf_api_token}
        # 也支持 alidns:
        # dns alidns {vault.dns.ali_access_key_id} {vault.dns.ali_access_key_secret}
        renew_before 30d
        storage vault kv/data/prod/fluxgate/certs   # 开启 Vault KV 多节点证书共享（可选，推荐开启）
    }

    ...
}
```

#### 4.2 Pingora 动态 SNI 与热替换

- 重构 [src/tls.rs](file:///Users/shenlan/workspaces/fluxgate/src/tls.rs)，使用 Pingora `TlsAccept`（基于 OpenSSL `ServerNameCallback` / SNI 回调）绑定全局 `DynamicCertStore`（`Arc<RwLock<CertIndex>>`）。
- 支持精确域名优先、泛域名（`*.svc.plus`）兜底匹配，支持新域名动态上线与证书续期后毫秒级原子替换（新建 TLS 握手立即生效，不中断已建立连接）。
- 如站点启用了 ACME 但首次启动尚无可用证书，支持短暂自签占位或阻塞等待首次签发完成后再对外健康就绪（可配置策略）。

#### 4.3 纯 Rust ACME v2 与首批 DNS Provider

- **ACME 协议栈**：基于 `instant-acme`（纯 Rust 异步 ACME v2 客户端）+ `rcgen`（生成 ECDSA P-256 密钥与 CSR）+ `x509-parser`（解析证书过期时间与 SAN）。
- **`DnsProvider` 统一抽象**：定义异步 `present(domain, fqdn, value)` 与 `cleanup(domain, fqdn, value)` 接口，并内置基于公共/权威 DNS 的 TXT 记录传播轮询等待。
- **首批内置 Provider**：
  1. **`cloudflare`**：使用 API Token（Zone Read + DNS Edit 权限）通过 Cloudflare v4 API 增删 `_acme-challenge.<domain>` TXT 记录。
  2. **`alidns`**：使用 AccessKey ID / AccessKey Secret（Aliyun OpenAPI v2/v3 签名）管理阿里云解析 DNS TXT 记录。

#### 4.4 Vault KV v2 多节点证书共享协同流程

为避免同一集群或同一池内多台节点同时向 Let's Encrypt 申请相同泛域名（如 `*.svc.plus`）导致触及速率限制，当配置 `storage vault <kv_path>` 时采用 **KV v2 CAS（Check-And-Set）乐观锁协同**：

1. **路径约定**：`<kv_path>/<san_group_key>`（如 `kv/data/prod/fluxgate/certs/wildcard.svc.plus`），内容包含 `cert_pem`、`key_pem`、`expires_at`、`issuer`、`updated_by`、`renew_lock_until`、`renew_owner`。
2. **启动 / 定期同步（Follower 同步）**：
   - 所有节点定期拉取 Vault 中的共享证书并落盘到受保护本地缓存目录（`/var/lib/fluxgate/certs`，权限 `0700` / 文件 `0600`）同时载入 `DynamicCertStore`。
   - 若 Vault 证书仍有效且未进入 `renew_before` 窗口，所有节点直接复用，**零 ACME 请求**。
3. **续期竞争与 CAS 互斥（Leader 续期）**：
   - 当证书缺失或剩余有效期 `< renew_before` 时，节点尝试通过 Vault KV v2 **`cas` 参数**写入租约锁字段（`renew_owner = <node_id>`，`renew_lock_until = now + 5m`）。
   - 仅 CAS 抢锁成功的唯一节点执行 DNS-01 Challenge 与 ACME 签发；其余节点短暂退避后重新读取 Vault KV，直接拉取新签发证书生效。
   - 签发成功后，Leader 原子写回最新 `cert_pem`/`key_pem`/`expires_at` 并释放锁；若失败则在租约过期后自动允许其他节点接管重试。

#### 4.5 TLS 与 ACME 监控指标

- `fluxgate_tls_cert_expiry_timestamp_seconds{domains="..."}`（Gauge: 证书过期 Unix 时间戳）
- `fluxgate_tls_cert_days_remaining{domains="..."}`（Gauge: 剩余有效天数）
- `fluxgate_acme_renew_total{domains="...",provider="cloudflare|alidns",result="success|error|skipped"}`（Counter）

---

## 3. 分阶段实施路线（Milestones）

### M1：热重载与动态 TLS 底座
- **涉及模块**：
  - [src/proxy/service.rs](file:///Users/shenlan/workspaces/fluxgate/src/proxy/service.rs) / [src/proxy/route.rs](file:///Users/shenlan/workspaces/fluxgate/src/proxy/route.rs)：引入 `ArcSwap<CompiledRouter>` 原子路由切换。
  - [src/tls.rs](file:///Users/shenlan/workspaces/fluxgate/src/tls.rs)：引入 `DynamicCertStore` 与 Pingora `TlsAccept` 动态 SNI 回调，兼容静态 `tls <cert> <key>`。
  - [src/cli.rs](file:///Users/shenlan/workspaces/fluxgate/src/cli.rs) / [src/main.rs](file:///Users/shenlan/workspaces/fluxgate/src/main.rs)：实现 `SIGHUP` 热重载循环、`fluxgate reload` 子命令与 reload 指标。
- **验收标准**：运行中发送 `fluxgate reload`，现有长流式连接不中断、新路由/新静态证书即时生效、错误配置自动回滚保留旧配置。

### M2：Vault KV v2 安全集成
- **涉及模块**：
  - 新增 `src/vault/`（`client.rs`、`auth.rs`、`store.rs`）：AppRole/Token 认证与续期、KV v2 轮询与 CAS 工具方法、`SecretStore`（`secrecy`/`zeroize`）。
  - [src/config/ast.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/ast.rs)、[src/config/parser.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/parser.rs)、[src/config/validate.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/validate.rs)：解析 `vault {}` 块、`{vault.*}` 占位符、`validate --offline` 与日志脱敏。
  - [src/metrics.rs](file:///Users/shenlan/workspaces/fluxgate/src/metrics.rs)：新增 Vault 同步指标。
- **验收标准**：`fluxgate` 启动后可从本地/测试 Vault KV v2 安全加载凭据，KV 版本更新自动触发依赖刷新，日志/错误信息零明文密钥泄漏，Vault 短暂断开时服务平稳降级。

### M3：ACME DNS-01 自动续期与 Vault KV 多节点证书共享
- **涉及模块**：
  - 新增 `src/acme/`（`client.rs`、`dns/mod.rs`、`dns/cloudflare.rs`、`dns/alidns.rs`、`storage.rs`、`scheduler.rs`）。
  - [src/config/](file:///Users/shenlan/workspaces/fluxgate/src/config/mod.rs)：支持 `tls { issuer acme ...; dns ...; renew_before ...; storage vault ... }` DSL 解析与校验。
  - [src/tls.rs](file:///Users/shenlan/workspaces/fluxgate/src/tls.rs) / [src/metrics.rs](file:///Users/shenlan/workspaces/fluxgate/src/metrics.rs)：对接 `DynamicCertStore` 自动热替换与到期/续期指标。
- **验收标准**：基于 mock/staging ACME 与 DNS API 验证 `cloudflare` / `alidns` DNS-01 签发与自动续期；验证两节点并发触发同一域名续期时，仅 CAS 抢锁成功节点向 ACME 发起签发，另一节点直接同步 Vault 证书并热替换生效。

### M4：GitOps 门禁与 Ansible Pull 端到端闭环
- **涉及模块**：
  - [src/cli.rs](file:///Users/shenlan/workspaces/fluxgate/src/cli.rs) / [src/config/validate.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/validate.rs)：`validate --strict-gitops` 与 `fluxgate doctor`。
  - [deploy/fluxgate.service](file:///Users/shenlan/workspaces/fluxgate/deploy/fluxgate.service)：补充 `ExecReload`、`EnvironmentFile` / `LoadCredential` 模板。
  - `ai-workspace-infra/playbooks`（跨仓库联动）：新增 `pull_fluxgate.yml` 并增强 `roles/vhosts/fluxgate`（按架构下载二进制 + `SHA256SUMS` 校验 + `ansible-pull-fluxgate.timer` + `validate -> reload`）。
- **验收标准**：`--strict-gitops` 可精准拦截明文密钥；单节点 `ansible-pull` 定时器可完成零停机 GitOps 配置更新与二进制安全升级。
