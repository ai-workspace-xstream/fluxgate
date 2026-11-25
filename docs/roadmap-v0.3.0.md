# Fluxgate v0.3.0 架构与特性规划（代号：蜂群分组模式 / Swarm Grouping Mode）

> **状态**：架构规划（Planning）  
> **基准版本**：`v0.2.1` (`6b5b4c0`)  
> **目标版本**：`v0.3.0`  
> **版本代号**：**蜂群分组模式（Swarm Grouping Mode）**

---

## 1. 目标与非功能约束

在 `v0.1.0`（Rust + Cloudflare Pingora 流式反向代理底座）与 `v0.2.x`（Vault KV v2 密钥同步、GitOps `ArcSwap` 零中断热重载、ACME DNS-01 + Vault CAS 多节点证书共享、低延迟 H2/h2c 流控优化）的基础上，`v0.3.0` 聚焦解决**同区域多边缘节点的去中心化轻量级负载均衡与过载无感自愈**。

以东京 Plus 节点池（`jp-xconnect-plus-01.svc.plus`、`jp-xconnect-plus-02.svc.plus`，以及后续随时水平扩展的 `-03`、`-04`... `-N`）为典型场景，`v0.3.0` 引入**蜂群分组模式（Swarm Grouping Mode）**。

### 1.1 核心设计原则与约束

1. **单机自治优先（Autonomous Ingress & Local-First）**
   - 摒弃传统“独立前置中心 LB 节点”架构（避免所有流量多绕一跳带来额外 RTT 与双倍带宽成本，同时消除前置 LB 单点故障）。
   - 每个节点既是独立的公网接入入口，也是蜂群中的计算与协同单元。
   - **水位正常时 100% 本地闭环**：只要本机负载低于高水位阈值（`high_watermark`）且本机后端（如 `unix///dev/shm/xray.sock`）健康，请求 100% 走本机 UDS 零拷贝路径，**跨机转发开销为 `0`**。
   - **断网/孤岛100% 自治**：即便对等节点全部失联或网络分区，本节点自动退化为标准独立节点，不影响本机既有与新建流量。
2. **过载与故障无感转移（1-Hop Zero-Perception Spillover & Failover）**
   - 当单节点遭遇突发流量洪峰（活跃流数、内存 RSS、事件循环延迟超过高水位）或本机后端进程短暂重启/异常时，Fluxgate 在 Pingora `upstream_peer()` 阶段，通过同区域常驻 **HTTP/2 TLS 多路复用连接池**，将超额新会话**透明溢出（Spillover）**至同蜂群内负载较低的健康节点。
   - 客户端无需断开重连、无需感知节点切换、无需等待公网 DNS TTL 收敛。
   - 严格执行 **1-Hop 防环路约束（`max_hops = 1`）**：任何经由蜂群溢出的请求在目标节点必须强制走本机后端落地，绝不二次转发。
3. **自由弹性扩缩容（Dynamic Peer Join / Leave）**
   - 新节点（如 `jp-xconnect-plus-03.svc.plus`）只需声明相同的蜂群分组 ID（`group "jp-plus"`）、同池共享密钥（`{vault.swarm.shared_key}`）及任一种子节点（Seed）或 DNS 发现域名，启动后 **2 秒内即可通过轻量级 Gossip 广播自动并入蜂群**，立刻分担过载节点溢出流量。
   - 节点优雅维护（`fluxgate swarm drain` 或 `SIGTERM`）或意外宕机时，蜂群在毫秒至秒级内自动将其从候选池摘除。
4. **L3 DNS GTM + L7 蜂群溢出双层协同（Dual-Plane Traffic Scheduling）**
   - **源头导流（DNS GTM 平面）**：直接复用 `v0.2.0` 的 Vault KV v2 密钥同步引擎（`{vault.dns.cf_api_token}` / `{vault.dns.ali_access_key_id}` + `{vault.dns.ali_access_key_secret}`）与 DNS Provider 底座（[src/acme/dns.rs](file:///Users/shenlan/workspaces/fluxgate/src/acme/dns.rs)），通过 Vault KV CAS 选主由蜂群唯一 Coordinator 节点驱动 **Cloudflare DNS / Cloudflare Load Balancing** 或 **阿里云智能云解析（AliDNS 权重 SLB + 智能地域/运营商线路）**，实现过载/故障节点源头摘除与**付费用户专属的百分比灰度发布（Canary Weight）**。
   - **毫秒兜底（L7 Pingora 蜂群溢出平面）**：在客户端 DNS 缓存（TTL）尚未过期的窗口期或瞬时脉冲洪峰下，由 L7 蜂群 1-Hop H2 连接池实现毫秒级无感兜底。
5. **严守 1 GiB 边缘节点资源红线**
   - 延续单二进制极简形态：蜂群心跳、Gossip 成员管理、DNS GTM 协调器、负载评分与会话粘滞表全部运行在现有 Pingora `BackgroundService` 与 Tokio Runtime 内，不引入 Consul / Etcd / Redis 等任何外部组件。
   - **内存预算**：蜂群控制面与固定容量分片会话粘滞表（`AffinityTable`）新增常驻内存严格控制在 **`< 2 MiB`**；请求热路径全面采用 `ArcSwap` 与原子指令，零全局互斥锁阻塞。

### 1.2 总体架构（L3 DNS GTM + L7 蜂群双层协同）

```
        Vault KV v2 (kv/data/prod/fluxgate/dns-tokens & gtm-policy)
                     │  1. {vault.dns.cf_api_token} / {vault.dns.ali_*} (Zeroize 内存驻留)
                     │  2. KV v2 CAS 乐观锁选主 (全群唯一 GTM Coordinator 避免 API 冲突)
                     ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │ L3 入口调度层: Cloudflare DNS / Paid LB  或  阿里云智能 DNS (AliDNS) │
   │  - 基础池: 动态增删 jp-xconnect-plus.svc.plus 健康未过载 A/AAAA 记录  │
   │  - 进阶/付费池: 按负载反比动态调节权重 + 灰度金丝雀比例 + 智能线路   │
   └─────────────────┬─────────────────────────────────┬─────────────────┘
                     │ 客户端解析导流 (秒~分钟级收敛)     │
                     ▼                                 ▼
       ┌───────────────────────────┐     ┌───────────────────────────┐
       │ jp-xconnect-plus-01       │     │ jp-xconnect-plus-02       │
       │ Fluxgate v0.3 (Load: 88%) │     │ Fluxgate v0.3 (Load: 25%) │
       ├───────────────────────────┤     ├───────────────────────────┤
       │ 1. 水位 <=70%: 本机 UDS    │     │ 接收直连 + 01 溢出流量     │
       │    /dev/shm/xray.sock     │     │ (X-Fluxgate-Swarm-Hop: 1  │
       │ 2. 水位 >70% (DNS TTL 窗):│     │  强制本机 UDS 落地，防环)  │
       │    L7 P2C 毫秒级溢出 ─────┼────►│  /dev/shm/xray.sock       │
       └─────────────▲─────────────┘     └─────────────▲─────────────┘
                     │  /_fluxgate/swarm/heartbeat     │
                     │  (H2 2s 轻量级指标与成员 Gossip)  │
                     └────────────────┬────────────────┘
                                      ▼
                     ┌─────────────────────────────────┐
                     │ jp-xconnect-plus-03 ... -0N     │
                     │ (自动加入 Gossip 并自动注册至    │
                     │  DNS GTM 池，支持 5%->100% 灰度) │
                     └─────────────────────────────────┘
```

---

## 2. 特性详细设计

### 特性 1：蜂群分组 DSL 与去中心化动态节点发现

**目标**：在不破坏 Caddyfile 声明式体验的前提下，让同区域多节点（`jp-xconnect-plus-01`、`jp-xconnect-plus-02` 及后续新节点）使用统一的配置模板即可组成自治蜂群。

#### 2.1.1 模块化 Drop-in DSL 声明规范（`/etc/fluxgate/conf.d/Swarm-Grouping-Mode.conf`）

利用 Fluxgate 现有的 `import /etc/fluxgate/conf.d/*.conf` 递归解析能力（[src/config/parser.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/parser.rs)），`v0.3.0` 支持**跨文件全局块合并（Multi-File Global Block Merging）**以及**顶层 `swarm { ... }` 块直接声明**：
- 主配置 `/etc/fluxgate/Fluxgatefile` 保持原有极简结构不变；
- 蜂群分组与 DNS GTM 策略作为独立功能插件放入 **`/etc/fluxgate/conf.d/Swarm-Grouping-Mode.conf`**（启用时投递该文件并 `fluxgate reload`，停用时删除该文件并 `fluxgate reload`，与 `xconnect-gateway` vhost drop-in 模式完全一致）。

**文件 1：主配置 `/etc/fluxgate/Fluxgatefile`（保持不变）**
```caddy
{
    grace_period 15s
    metrics 127.0.0.1:9102
}

import /etc/fluxgate/conf.d/*.conf
```

**文件 2：蜂群分组独立配置 `/etc/fluxgate/conf.d/Swarm-Grouping-Mode.conf`**
（同时兼容外层包裹 `{ ... }` 全局块或直接顶层声明 `swarm { ... }`；多文件中的 `vault.sync` 条目自动增量合并）：
```caddy
# /etc/fluxgate/conf.d/Swarm-Grouping-Mode.conf
{
    vault {
        addr env(VAULT_ADDR)
        auth approle
        sync swarm kv/data/prod/fluxgate/swarm 5m
        sync dns   kv/data/prod/fluxgate/dns-tokens 5m
    }

    # Fluxgate v0.3 蜂群分组配置（也可省略外层 { } 直接在顶层写 swarm { ... }）
    swarm {
        group               "jp-plus"
        region              "jpn-tky"
        node_id             env(AGENT_ID)                       # 例: jp-xconnect-plus-01.svc.plus
        advertise           env(AGENT_PROXY_DOMAIN):443         # 对等节点连入地址与端口
        shared_key          {vault.swarm.shared_key}            # HMAC-SHA256 蜂群内部鉴权密钥

        # 节点发现：支持静态种子 + DNS 自动发现（新节点连上任一 seed 即自动 Gossip 扩散至全群）
        seeds               jp-xconnect-plus-01.svc.plus:443 jp-xconnect-plus-02.svc.plus:443
        dns_discover        _fluxgate-swarm._tcp.jp-plus.svc.plus   # 可选：DNS SRV 或多 A 记录发现

        probe_interval      2s                                  # 心跳与指标交换周期
        peer_timeout        6s                                  # 连续 3 个周期无响应标记为 Down
        low_watermark       70                                  # <= 70 分：100% 本地 UDS 处理
        high_watermark      85                                  # 70 ~ 85 分：按比例渐进溢出；>= 85 分：新会话全面溢出
        max_active_streams  256                                 # 单机最佳并发活跃流参考基线
        max_memory_mb       350                                 # 单机进程 RSS 内存安全水位基线 (MiB)
        hysteresis          15                                  # 目标 Peer 负载分必须比本机低 15 分以上才触发转移

        # L3 DNS 轻量级 GTM 调度、ExternalDNS 免手动自动注册与灰度切流
        gtm {
            enabled             true
            entrypoint          "jp-xconnect-plus.svc.plus"     # 蜂群统一接入域名
            # 类 ExternalDNS 全程免手动 DNS：节点启动自动探测公网 IP 并自动 insert/update 三类记录
            # (1) 单机域名: jp-xconnect-plus-01.svc.plus -> 本机公网 IPv4/IPv6
            # (2) 蜂群发现记录: _fluxgate-swarm._tcp.jp-plus.svc.plus (SRV / 多 A)
            # (3) 蜂群统一入口: jp-xconnect-plus.svc.plus (多 A / 权重 SLB)
            auto_register       true                            # 开启 ExternalDNS 风格自动 insert/upsert
            public_ip           auto                            # auto (网卡公网 IP + STUN/HTTPS 探测) 或显式指定 IP
            ownership_txt       true                            # 维护 _fluxgate-owner.<fqdn> TXT 所有权签名，防误删非托管记录
            cleanup_on_drain    true                            # 节点 drain / 下线时自动清理其 GTM 与发现记录

            # 主流规范 DNS 服务商插件化接入 (统一通过 Vault KV 加载 API Key):
            provider            cloudflare {vault.dns.cf_api_token}
            # 阿里云云解析 AliDNS (支持权重 SLB 与分地域/运营商智能线路):
            # provider          alidns {vault.dns.ali_access_key_id} {vault.dns.ali_access_key_secret}
            # AWS Route 53 (SigV4 签名，支持 Weighted / Latency Routing):
            # provider          route53 {vault.dns.aws_access_key_id} {vault.dns.aws_secret_access_key} zone_id={vault.dns.aws_zone_id}
            # 腾讯云 DNSPod (TC3-HMAC-SHA256 签名，支持权重与分线路):
            # provider          dnspod {vault.dns.dnspod_secret_id} {vault.dns.dnspod_secret_key}

            mode                weighted_canary                 # multi_a | weighted_canary | cloudflare_lb
            reconcile_interval  15s                             # GTM Coordinator 巡检对账周期
            ttl                 60                              # DNS 记录 TTL (秒)
            min_healthy_nodes   1                               # 保底最少保留 A 记录数，严禁清空全部解析
            lock_storage        vault kv/data/prod/fluxgate/gtm-locks
            canary_policy       vault kv/data/prod/fluxgate/gtm-canary   # 可选：动态加载各节点灰度权重
        }
    }
}
```

**文件 3：站点路由配置 `/etc/fluxgate/conf.d/jp-xconnect.conf`**
```caddy
jp-xconnect-plus-01.svc.plus jp-xconnect-plus-02.svc.plus jp-xconnect-plus.svc.plus {
    tls /etc/fluxgate/tls/agent-proxy.crt /etc/fluxgate/tls/agent-proxy.key

    @xhttp {
        path /split /split/*
    }

    @xhttp_root path /split
    rewrite @xhttp_root /split/

    handle @xhttp {
        uri query -x_padding

        reverse_proxy unix///dev/shm/xray.sock {
            flush_interval -1
            transport http {
                versions h2c 2
            }
            # 蜂群无感分流策略（当 conf.d/Swarm-Grouping-Mode.conf 存在并启用时生效；未启用时自动忽略）
            swarm_spillover {
                enabled                 true
                affinity                path_segment 2          # 提取 /split/<session_id> 第 2 段做会话粘滞
                affinity_ttl            120s
                fallback_on_local_error true                    # 本机 UDS 连接失败时即时 Failover 至健康 Peer
            }
        }
    }

    respond "XConnect Edge Agent"
}
```

#### 2.1.2 三级融合节点发现机制（自由加入更多节点）

1. **Seed Gossip 自动扩散（零存量节点配置修改）**
   - 每个节点维护一张轻量级成员表 `PeerTable`（包含 `node_id`、`advertise_addr`、`region`、`group`、`state`、`load_score`、`rtt_ms`、`last_seen_unix`、`incarnation`）。
   - 当新节点 `jp-xconnect-plus-03.svc.plus` 启动时，它读取自身配置中的 `seeds`（如 `01` 和 `02`），发起 `/_fluxgate/swarm/heartbeat` 心跳。
   - `01` 校验 `group == "jp-plus"`、`region == "jpn-tky"` 及 `shared_key` HMAC 签名通过后，将 `03` 写入自身 `PeerTable`，并在心跳响应的 `peers` 列表中返回全量已知存活成员。
   - 下一个心跳周期（`2s` 内），全群所有节点均自动获知 `03` 的存在并建立健康探测，无需修改 `01` 和 `02` 的配置文件。
2. **DNS 多 A / SRV 记录轮询发现（可选）**
   - 若配置 `dns_discover`，后台每 `30s` 异步解析一次域名下的所有 A/AAAA 或 SRV 记录，自动将新出现的节点并入候选探测列表。
3. **GitOps + Ansible Pull 声明热更新**
   - 当 GitOps 拓扑更新并触发 `fluxgate reload` 时，`ArcSwap` 热更新种子列表，保留运行时已建立的 Peer 动态负载统计与 H2 连接池。

#### 2.1.3 节点生命周期与优雅排空（Graceful Drain）

- 节点状态机：`Joining` $\to$ `Alive` $\to$ `Draining` / `Suspect` $\to$ `Down`。
- 当节点准备维护重启或收到 `fluxgate swarm drain` 指令时，主动将自身广播状态置为 `Draining`（对外广播 `load_score = 100`）：
  - 其他对等节点立即停止向该节点分配新的溢出会话；
  - 该节点可根据策略将新到达的会话主动溢出给其他 `Alive` 节点，待存量长连接在 `grace_period` 内自然结束后安全下线。

---

### 特性 2：轻量级对等心跳与多维负载水位评估

**目标**：以极低 CPU/内存与网络开销（单次心跳 JSON `< 512 Bytes`），让蜂群内每个节点实时掌握全群健康度与精确负载水位。

#### 2.2.1 内部心跳协议与 HMAC 安全鉴权

- **内置控制端点**：`POST /_fluxgate/swarm/heartbeat`（在 `FluxgateProxy::request_filter` 最前置拦截，不落入业务路由，也不写入普通访问日志）。
- **防伪造与防重放鉴权**：
  - 请求头必须携带：
    - `X-Fluxgate-Swarm-Node: <node_id>`
    - `X-Fluxgate-Swarm-Group: <group>`
    - `X-Fluxgate-Swarm-Ts: <unix_epoch_secs>`（要求与接收方时钟偏差 $|\Delta t| \le 30\text{s}$）
    - `X-Fluxgate-Swarm-Sig: <hex(HMAC-SHA256(shared_key, method + path + ts + body_sha256))>`
  - 鉴权失败或未启用 `swarm` 时直接返回 `404 Not Found`（隐藏内部端点特征）。
- **心跳载荷结构**：
  ```json
  {
    "node_id": "jp-xconnect-plus-01.svc.plus",
    "group": "jp-plus",
    "region": "jpn-tky",
    "advertise": "jp-xconnect-plus-01.svc.plus:443",
    "incarnation": 1795584000,
    "state": "Alive",
    "metrics": {
      "load_score": 82,
      "active_streams": 210,
      "rss_bytes": 110100480,
      "ewma_latency_ms": 18.4,
      "local_uds_healthy": true
    },
    "known_peers": [
      { "node_id": "jp-xconnect-plus-02.svc.plus", "advertise": "jp-xconnect-plus-02.svc.plus:443", "state": "Alive" },
      { "node_id": "jp-xconnect-plus-03.svc.plus", "advertise": "jp-xconnect-plus-03.svc.plus:443", "state": "Alive" }
    ]
  }
  ```

#### 2.2.2 多维归一化负载分（Load Score）计算模型

每个节点在后台每 `1s` 基于无锁原子指标计算一次综合负载分 $S \in [0, 100]$：

$$S = \min\left(100,\; \max\left(S_{\text{weighted}},\; S_{\text{memory\_cap}},\; S_{\text{uds\_health}}\right)\right)$$

其中：
1. **加权基础负载分 $S_{\text{weighted}}$**：
   $$S_{\text{weighted}} = 100 \times \left( 0.55 \cdot \min\left(1.0, \frac{\text{ActiveStreams}}{\text{MaxActiveStreams}}\right) + 0.25 \cdot \min\left(1.0, \frac{\text{RSS\_MB}}{\text{MaxMemoryMB}}\right) + 0.20 \cdot \min\left(1.0, \frac{\text{EWMA\_Latency}}{\text{TargetLatency}}\right) \right)$$
2. **内存保护硬顶 $S_{\text{memory\_cap}}$**：
   - 当进程 RSS 超过 `0.85 * MaxMemoryMB` 时，$S_{\text{memory\_cap}}$ 线性拉升至 `90~100`，优先保护 1 GiB 边缘机免受 OOM 威胁。
3. **本机后端健康度 $S_{\text{uds\_health}}$**：
   - 若本机 `/dev/shm/xray.sock` 连续连接失败或近期 502 错误率突增，$S_{\text{uds\_health}} = 100$（触发 100% 故障转移至健康对等节点）。

#### 2.2.3 三段式水位门控与防抖动滞回（Hysteresis）

为避免两台负载相近的节点互相把流量推给对方导致乒乓震荡，引入滞回差值 $\Delta$（默认 `hysteresis = 15`）：
- **绿色自治区间（$S \le \text{low\_watermark}$，默认 `70`）**：
  - 溢出率 $P_{\text{spill}} = 0\%$，所有请求 100% 走本机 UDS。
- **黄色渐进分流区间（$\text{low\_watermark} < S < \text{high\_watermark}$，默认 `70 ~ 85`）**：
  - 仅当蜂群中存在健康 Peer 满足 $S_{\text{peer}} + \Delta \le S_{\text{local}}$ 时，对**新建会话**以概率 $P_{\text{spill}} = \frac{S_{\text{local}} - \text{low\_watermark}}{\text{high\_watermark} - \text{low\_watermark}}$ 渐进分流；已在本机建立的会话保持不动。
- **红色过载/故障保护区间（$S \ge \text{high\_watermark}$ 或本机 UDS 不可用）**：
  - 所有新建会话 100% 溢出至满足 $S_{\text{peer}} < \text{high\_watermark}$ 的健康对等节点；若全群所有节点均 $\ge \text{high\_watermark}$，则退回本机消化，避免无效跨机折返。

---

### 特性 3：防“羊群效应”选路、XHTTP 会话粘滞与 1-Hop 透明转发

**目标**：在多节点蜂群（3 节点及以上）中均匀打散溢出流量，并确保 XConnect `vless-xhttp` 流式协议的上下行子请求严格落入同一台节点的 Xray 实例。

#### 3.1 Power of Two Choices (P2C) + RTT 惩罚选路

当蜂群拥有 $N$ 台节点（如 `01`, `02`, `03`, `04`）时，若单纯将溢出流量全部发往“当前负载最低的第 1 名”，会在 `2s` 心跳窗口内瞬间打爆该空闲节点（羊群效应）。
- **P2C 有效负载分定义**：
  $$\text{EffectiveCost}(\text{peer}) = S_{\text{peer}} + \alpha \cdot \text{RTT}_{\text{ms}}(\text{peer}) + \beta \cdot \text{InFlightSpillover}(\text{peer})$$
  其中 `InFlightSpillover(peer)` 是本节点当前正在向该 Peer 转发的活跃流原子计数（即时反馈，无需等待下一轮 2s 心跳！）。
- **选路步骤**：
  1. 过滤出同 `group`、同 `region`、状态为 `Alive` 且 $S_{\text{peer}} + \Delta \le S_{\text{local}}$ 的候选集；
  2. 若候选集大小为 `1`（例如仅 `01` 与 `02` 两节点），直接选中该节点；
  3. 若候选集大小 $\ge 2$，使用线程局部快速随机数（`fastrand`）无放回随机抽取 **2 台候选 Peer**，选择其中 $\text{EffectiveCost}$ 更低的一台。

#### 3.2 XHTTP 会话粘滞（Session Affinity）

Xray 的 XHTTP 传输层（`packet-up` / `stream-up` / `stream-one`）将一个逻辑代理会话拆分为多个带有相同 `<session_id>` 的 HTTP/2 请求（如 `POST /split/<session_id>/0` 与 `GET /split/<session_id>`）。若同一个 `<session_id>` 的 GET 和 POST 被分流到不同机器的 Xray，连接会立即失败。
- **会话 Key 提取策略**：
  - `affinity path_segment 2`：零分配提取 URI 路径第 2 段（如 `/split/a8f9c2e1-xxxx/0` $\to$ `a8f9c2e1-xxxx`）；
  - 若请求不包含子路径 `<session_id>`，自动回退为 `ClientIP` 哈希粘滞。
- **固定大小分片无锁/微锁粘滞表（`AffinityTable`）**：
  - 采用 `64` 分片（Shard），每分片固定容量 `256` 槽位（总计 `16,384` 个活跃会话槽位，每槽位仅存储 `u64` SipHash 指纹、`u16` 目标节点索引与 `u32` 秒级时间戳，总内存仅 **`~256 KiB`**）。
  - **粘滞决策流程**：
    1. 计算 `session_key` 的 64 位哈希，查询对应分片槽位；
    2. 若命中且未过期（`< affinity_ttl`）：
       - 目标为 `Target::Local` $\to$ 继续走本机 UDS（保证已建流会话在中途水位升高时不断流）；
       - 目标为 `Target::Peer(peer_id)` 且该 Peer 仍 `Alive` $\to$ 继续发往该 Peer；
    3. 若未命中（全新会话）：按当前水位与 P2C 算法决定 `Target::Local` 或 `Target::Peer(peer_id)`，并写入槽位。

#### 3.3 1-Hop 防环路保护与 Pingora H2 连接池复用

1. **1-Hop 严格防环路（Loop Prevention）**
   - 当节点 A 决定将请求溢出至节点 B 时，在 `upstream_request_filter()` 注入：
     - `X-Fluxgate-Swarm-Hop: <node_a_id>`
     - `X-Fluxgate-Swarm-Origin-IP: <client_ip>`
     - `X-Fluxgate-Swarm-Sig: <hmac_sig>`
   - 节点 B 在 `request_filter()` 中检测到 `X-Fluxgate-Swarm-Hop` 时：
     - 校验 `X-Fluxgate-Swarm-Sig`；若签名非法，记录 `fluxgate_swarm_invalid_sig_total` 并拒绝（防止外部伪造请求绕过限流或探测拓扑）；
     - 若签名合法，在 `FluxgateCtx` 标记 `force_local_upstream = true`，**无条件走节点 B 本机 UDS `/dev/shm/xray.sock`**，绝不再次进入 `swarm_spillover` 选路，从协议层保证最多只经过 1 次跨机转发。
2. **复用 Pingora 全局 HTTP/2 TLS 连接池**
   - 在 `upstream_peer()` 中，当路由目标为 `UpstreamTarget::SwarmPeer { addr, sni }` 时，构造 `HttpPeer::new(addr, true, sni)`：
     - 开启 TLS + ALPN `h2`（`peer.options.alpn = ALPN::H2`）；
     - 对齐 `v0.2.1` 流控参数：`max_h2_streams = 256`、`h2_stream_window_size = 4 MiB`、`h2_connection_window_size = 16 MiB`、`tcp_fast_open = true`、`tcp_keepalive = 60s`；
     - Pingora 自动在节点 A 与节点 B 之间复用长寿命 H2 TLS 连接并多路复用 Stream，**溢出请求无需经历 TCP 三次握手与 TLS 握手，同区域（如东京机器间 `< 1.5 ms`）转发延迟几乎不可感知**。
3. **本机 UDS 故障即时 Failover**
   - 当本机水位原本正常（选路为 `Local`），但在连接 `/dev/shm/xray.sock` 时触发 `fail_to_connect`（如本机 Xray 正在重启），若开启了 `fallback_on_local_error true` 且请求尚未发送 Body，Pingora 自动在同一请求生命周期内重选健康 Swarm Peer 进行重试，对外屏蔽单机后端闪断。

---

### 特性 4：类 ExternalDNS 全程免手动 DNS 自动注册 + 轻量级 GTM 流量调度与灰度切流

**目标**：借鉴 Kubernetes `external-dns` 的自动化设计理念，在接入主流规范 DNS 服务商 API Key（通过 Vault KV v2 安全注入）的前提下，实现**从新节点开机、单机域名 insert、蜂群发现种子注册，到统一入口域名 GTM 权重调优与下线清理的全生命周期免手动 DNS 运维**。

#### 4.1 为什么采用“ExternalDNS 自动注册 + DNS GTM + L7 蜂群溢出”协同？

| 维度 | L3 ExternalDNS 自动注册 & GTM 平面 | L7 Pingora 蜂群溢出平面（Swarm Spillover） |
| :--- | :--- | :--- |
| **运维体验** | **全程免手动改 DNS**：新节点 `jp-xconnect-plus-03` 开机即自动探测公网 IP 并 insert 自身 `A`/`AAAA`、蜂群发现 `SRV`/`A` 及统一入口 `jp-xconnect-plus.svc.plus` 记录。 | **零配置自动建连**：通过 DNS 发现记录或种子 Gossip 2 秒内自动建立 H2 跨机溢出通道。 |
| **作用阶段** | 客户端建连前（DNS 解析阶段，`15s ~ 60s` 收敛） | 客户端已建连（HTTP/2 请求路由阶段，**`< 2 ms` 即时生效**） |
| **核心价值** | **源头治本**：免除人工去 Cloudflare/阿里云后台增删改 IP 的繁琐操作；将新建客户端连接直接导向低负载节点或按灰度比例切流。 | **实时兜底**：吸收 DNS TTL 缓存窗口期内的存量请求、瞬时流量尖峰以及本机 Xray 重启的秒级闪断。 |

#### 4.2 类 ExternalDNS 全程免手动 DNS 生命周期管理（Zero-Touch DNS Auto-Insert）

当 `gtm { auto_register true }` 启用且 Vault KV 提供了有效 DNS API Key 时，Fluxgate 自动接管以下三类 DNS 记录的 `insert / upsert / delete` 闭环：

1. **三类自动化 DNS 记录**
   - **① 单机专属直连记录（Node Self Record）**：
     - 节点启动时自动检测本机公网 IPv4 / IPv6（优先读取主网卡公网地址，若处于云厂商 1:1 NAT 环境则通过多源 HTTPS/STUN 接口交叉确认公网出口 IP）。
     - 节点自身自动调用 DNS Provider API 将 `<node_id>`（如 `jp-xconnect-plus-03.svc.plus`）以及本机声明的独立业务站点域名（如 `jp-xconnect-gateway-02.svc.plus`）自动 `insert` 或更新至当前公网 IP（主机更换弹性 IP 重启后自动自愈更新）。
   - **② 蜂群自发现种子记录（Swarm Discovery Record）**：
     - 自动将本节点 IP / 端口注册到 `dns_discover` 域名（如 `_fluxgate-swarm._tcp.jp-plus.svc.plus` `SRV` 记录或 `swarm-jp-plus.svc.plus` 多 `A` 记录）。
     - **彻底告别静态 `seeds` 维护**：哪怕配置文件中一行 `seeds` 都不写，任何新节点只要配置了相同的 `group "jp-plus"` 与 DNS Provider，开机查询 `dns_discover` 域名即可发现存量蜂群并自动加入。
   - **③ 蜂群统一入口 GTM 记录（Pool Entrypoint Record）**：
     - 由持有 Vault CAS 锁的 GTM Coordinator 根据全群健康状态、实时负载分 $S_i$ 与灰度权重 $\gamma_i$，自动向统一入口域名（如 `jp-xconnect-plus.svc.plus`）批量 `insert` 新加入的健康节点记录、更新权重或摘除过载/下线节点。
2. **ExternalDNS 风格 TXT 所有权注册表（Ownership Registry — 严防误删非托管记录）**
   - 完全对齐 Kubernetes `external-dns` 安全规范：Fluxgate 自动 `insert` 任何 DNS 记录时，同步写入伴生 TXT 所有权签名记录 `_fluxgate-owner.<fqdn>`（以及云厂商原生 Record `comment` / `remark` 字段）：
     ```text
     "heritage=fluxgate,fluxgate/group=jp-plus,fluxgate/owner=jp-xconnect-plus-03.svc.plus,fluxgate/resource=gtm"
     ```
   - **安全铁律**：Fluxgate 的 Reconciler **仅允许修改或删除带有 `heritage=fluxgate` 且 `fluxgate/group` 匹配的记录**；对于运维人员手工在控制台创建的非托管记录（或无所有权 TXT 的存量记录，除非开启 `adopt_existing true`），只读不删，确保生产域名绝对安全。

#### 4.3 主流规范 DNS 服务商插件化矩阵（`DnsRecordProvider` 标准接口）

将 `v0.2.0` 原有仅面向 ACME `_acme-challenge` TXT 记录的 `DnsProvider` 抽象升级为完整的 **`DnsRecordProvider` 标准接口**（统一封装 `list_records`、`upsert_record`、`delete_record`、`update_weight`），所有凭据均通过 `{vault.dns.*}` 内存注入：

| DNS 服务商 (`provider`) | 认证方式（Vault KV 引用） | 核心支持能力与规范 API |
| :--- | :--- | :--- |
| **`cloudflare`** | `{vault.dns.cf_api_token}`（Bearer Token，Zone DNS Edit 权限） | Cloudflare API v4 `/zones/:id/dns_records`（自动 `insert`/`PATCH`/`DELETE` `A`/`AAAA`/`SRV`/`TXT` 及 `comment` 所有权标记）+ 付费版 Load Balancer Pools API。 |
| **`alidns`**（阿里云智能 DNS） | `{vault.dns.ali_access_key_id}` + `{vault.dns.ali_access_key_secret}` | 阿里云 OpenAPI v2/v3（`AddDomainRecord` / `UpdateDomainRecord` / `SetDNSSLBStatus` / `UpdateDNSSLBWeight` / `UpdateDomainRecordRemark`），原生支持 `1~100` 权重 SLB 与分运营商/分地域智能线路（`default` / `overseas` / `telecom` / `unicom` / `mobile`）。 |
| **`route53`**（AWS Route 53） | `{vault.dns.aws_access_key_id}` + `{vault.dns.aws_secret_access_key}` | 纯 Rust AWS SigV4 签名调用 `ChangeResourceRecordSets`（`UPSERT` / `DELETE`），原生支持 `SetIdentifier` + `Weight`（`0~255` 加权路由）与 `Region` 延迟路由。 |
| **`dnspod`**（腾讯云 DNSPod） | `{vault.dns.dnspod_secret_id}` + `{vault.dns.dnspod_secret_key}` | 腾讯云 API v3 `TC3-HMAC-SHA256` 签名（`CreateRecord` / `ModifyRecord` / `DeleteRecord`），支持记录级 `Weight`（`1~100`）与分线路智能解析。 |

#### 4.4 Vault KV v2 凭据加载与 CAS 选主协调（防 API 并发冲突）

1. **API 凭据全内存驻留（Zeroize）**
   - 通过 `vault { sync dns kv/data/prod/fluxgate/dns-tokens 5m }` 动态加载 `{vault.dns.cf_api_token}` 或 `{vault.dns.ali_access_key_id}` / `{vault.dns.ali_access_key_secret}`。
   - 凭据使用 `Zeroizing<String>` 封装，严格通过 `--strict-gitops` 校验，禁止任何明文 API Key 出现在 `Fluxgatefile` 或 Git 仓库。
2. **Vault KV CAS 唯一 Coordinator 选主**
   - 为避免蜂群内 $N$ 台节点同时调用 Cloudflare / 阿里云 DNS API 修改统一入口域名（如 `jp-xconnect-plus.svc.plus`）造成竞态或触发 API Rate Limit，复用 [src/acme/storage.rs](file:///Users/shenlan/workspaces/fluxgate/src/acme/storage.rs) 已验证的 **Vault KV v2 CAS（Check-And-Set）乐观锁租约机制**：
   - 路径：`kv/data/prod/fluxgate/gtm-locks/<group>`（如 `jp-plus`），租约字段包含 `coordinator_node_id`、`lease_until_unix`（默认 `45s`）、`last_dns_hash`。
   - **仅持有有效 CAS 租约的唯一 Coordinator 节点**每 `15s` 汇总全蜂群 Gossip 负载表并对比目标 DNS 状态；仅当节点健康集或权重分档发生实质变化时才发起 DNS API 调用（幂等差分更新）。
   - 若 Coordinator 节点宕机或维护下线，租约到期后其余 `Alive` 节点自动通过 CAS 接管 Coordinator 角色。

#### 4.5 三级 GTM 调度与付费高级灰度切流能力

1. **Tier 1：Cloudflare 标准版 — 动态多 A/AAAA 健康池（Zero-Cost Multi-A Pool）**
   - 适用场景：免费/标准 Cloudflare DNS 区域，低成本实现高可用与过载保护。
   - 调度逻辑：
     - 统一入口域名 `jp-xconnect-plus.svc.plus` 同时挂载蜂群内所有状态为 `Alive` 且 $S_i < \text{high\_watermark}$ 的节点公网 IP（`proxied = false`，`ttl = 60`），同时保留各节点独立域名（`jp-xconnect-plus-01.svc.plus`、`jp-xconnect-plus-02.svc.plus`）不变。
     - 当 `01` 节点过载（$S_1 \ge 85$）、进入 `Draining` 或宕机时，Coordinator 自动调用 Cloudflare API `DELETE /zones/:zone_id/dns_records/:record_id` 将 `01` 的 IP 从统一入口 `jp-xconnect-plus.svc.plus` 临时摘除，新客户端解析 100% 落入 `02` 及其他健康节点；
     - 当 `01` 负载回落至 $S_1 \le \text{low\_watermark}$（`70`）并稳定保持 2 个周期后，自动重新挂载回统一入口池。
     - **保底安全阀（`min_healthy_nodes = 1`）**：若全群所有节点均超过 `high_watermark`，保留负载相对最低的节点记录，**绝不清空域名的全部 A 记录**。
2. **Tier 2：阿里云智能云解析（AliDNS）— 动态权重 SLB + 灰度切流 + 智能地域/运营商线路**
   - 适用场景：国内/亚太跨境高质量接入、付费团队池（Plus / Pro / Team）精细化灰度发布与智能线路调度。
   - 调度逻辑（扩展 [src/acme/dns.rs](file:///Users/shenlan/workspaces/fluxgate/src/acme/dns.rs) 中的 `AliDnsProvider`）：
     - **开启权重负载均衡**：调用阿里云 OpenAPI `SetDNSSLBStatus` 开启 `jp-xconnect-plus.svc.plus` 子域名权重路由；
     - **基于实时负载与灰度比例的动态权重计算**：
       每个健康节点 $i$ 的目标 DNS 权重 $W_i \in [1, 100]$ 由**实时空闲容量**与**灰度系数 $\gamma_i \in [0.0, 1.0]$** 共同决定：
       $$W_i = \max\left(1,\; \text{round}\left((100 - S_i) \times \gamma_i\right)\right)$$
     - **付费用户高级流量灰度切换（Canary Rollout）**：
       运维或控制面可在 Vault KV `kv/data/prod/fluxgate/gtm-canary/jp-plus` 中动态写入灰度策略（无需重启 Fluxgate，由 `VaultSyncService` 热同步）：
       ```json
       {
         "canary_weights": {
           "jp-xconnect-plus-01.svc.plus": 1.0,
           "jp-xconnect-plus-02.svc.plus": 1.0,
           "jp-xconnect-plus-03.svc.plus": 0.10
         },
         "lines": {
           "jp-xconnect-plus-01.svc.plus": "default",
           "jp-xconnect-plus-02.svc.plus": "overseas"
         }
       }
       ```
       新节点 `jp-xconnect-plus-03` 上线初期可先分配 `10%`（`0.10`）灰度权重观察稳定性，验证无误后通过修改 Vault KV 渐进调升至 `50% -> 100%`；若异常则一键置为 `0.0` 秒级切走。
     - **分线路智能解析（Geo / ISP Line Routing）**：支持按阿里云解析线路（`default`、`telecom`、`unicom`、`mobile`、`overseas`）绑定最优节点。
3. **Tier 3：Cloudflare Paid Load Balancing — 动态 Steering 权重池与地理位置路由**
   - 适用场景：已开通 Cloudflare Load Balancing 付费订阅的高级租户/专有池。
   - 调度逻辑：通过 Cloudflare Load Balancer Pools API（`PATCH /accounts/:account_id/load_balancers/pools/:pool_id`）实时更新各 Origin（`jp-xconnect-plus-01`, `02`, `03`）的 `weight`（`0.00 ~ 1.00`）与 `enabled` 状态，配合 Cloudflare `dynamic_latency` 或 `random` Steering Policy 实现全球/区域级精确百分比灰度与自动容灾。

---

### 特性 5：可观测性、CLI 诊断与 GitOps 联动

#### 2.5.1 Prometheus 监控指标（`/metrics`）

在 [src/metrics.rs](file:///Users/shenlan/workspaces/fluxgate/src/metrics.rs) 新增以下蜂群与 GTM 专属指标：
- `fluxgate_swarm_load_score{group="jp-plus",node_id="..."}`（Gauge `0~100`：本机实时综合负载分）
- `fluxgate_swarm_peers_total{group="jp-plus",state="alive|suspect|draining|down"}`（Gauge：蜂群各状态节点数）
- `fluxgate_swarm_peer_load_score{group="jp-plus",peer="jp-xconnect-plus-02.svc.plus"}`（Gauge：本机视角下各对等节点的负载分）
- `fluxgate_swarm_peer_rtt_seconds{group="jp-plus",peer="..."}`（Gauge：与各对等节点的心跳 RTT）
- `fluxgate_swarm_decisions_total{group="jp-plus",decision="local|spillover|failover|forced_local_hop"}`（Counter：选路决策分布）
- `fluxgate_swarm_spillover_requests_total{group="jp-plus",target_peer="..."}`（Counter：溢出至各 Peer 的请求数）
- `fluxgate_swarm_spillover_active_streams{group="jp-plus",target_peer="..."}`（Gauge：当前正溢出至各 Peer 的并发流数）
- `fluxgate_swarm_local_active_streams{group="jp-plus",node_id="..."}`（Gauge：本机 UDS 当前活跃连接/流数，对标 HAProxy `show stat` 的 `scur`，用于排空归零验收）
- `fluxgate_swarm_manual_weight{group="jp-plus",target="local|<peer>"}`（Gauge `0~100`：当前人工覆写的运行时调度权重；未覆写时为 `-1`）
- `fluxgate_gtm_is_coordinator{group="jp-plus"}`（Gauge `1`/`0`：本节点是否持有当前 GTM Coordinator CAS 锁）
- `fluxgate_gtm_node_weight{group="jp-plus",entrypoint="jp-xconnect-plus.svc.plus",node="...",provider="cloudflare|alidns"}`（Gauge：当前生效的各节点 DNS GTM 权重/挂载状态）
- `fluxgate_gtm_reconcile_total{group="jp-plus",provider="cloudflare|alidns",result="updated|noop|error"}`（Counter：DNS GTM 对账结果计数）

#### 2.5.2 本地 `admin.sock` 运行时权重热调度（对标 HAProxy `admin.sock`）

在滚动升级与慢节点应急处置场景下，仅靠“全量 `drain`（0/100）”或等待 DNS TTL 往往粒度过粗。参考生产已验证的 HAProxy 3.0 零中断切流实践（`echo "set server be_xray_xhttp/xray weight 0" | socat stdio /run/haproxy/admin.sock`），`v0.3.0` 新增**无须 `reload`、不断存量长连接的运行时本地权重热调度能力**：

1. **本地管理 Socket 与轻量文本协议（`/run/fluxgate/admin.sock`，`mode 0660`）**
   - 在 `swarm { ... }` 中默认开启 `admin_socket /run/fluxgate/admin.sock`（仅限本机 `root` / `fluxgate` 组读写，不暴露公网端口）。
   - 同时支持 `fluxgate swarm weight ...` CLI 与 `socat stdio /run/fluxgate/admin.sock` 文本指令，直接复用运维习惯：
     ```bash
     # 1. 渐进灰度切流：80/20 -> 50/50 -> 20/80 -> 0/100（无需 reload，存量长连接不断）
     echo "set weight local 80" | socat stdio /run/fluxgate/admin.sock
     echo "set weight jp-xconnect-02.svc.plus 20" | socat stdio /run/fluxgate/admin.sock

     echo "set weight local 0" | socat stdio /run/fluxgate/admin.sock
     echo "set weight jp-xconnect-02.svc.plus 100" | socat stdio /run/fluxgate/admin.sock

     # 等价 CLI（支持可选 --ttl 防止运维忘记恢复，超时自动回退至自动水位模式）
     fluxgate swarm weight set local=0 jp-xconnect-02.svc.plus=100 --ttl 30m

     # 2. 实时观测本机与各 Peer 活跃连接数与生效权重（对标 HAProxy show stat）
     echo "show stat" | socat stdio /run/fluxgate/admin.sock
     # 输出示例（CSV，兼容既有脚本与监控解析）：
     # target,scur,status,weight,mode
     # local,0,UP,0,manual
     # jp-xconnect-02.svc.plus,14,UP,100,manual

     # 3. 恢复自动水位自治模式
     echo "reset weight" | socat stdio /run/fluxgate/admin.sock
     # 或 fluxgate swarm weight reset
     ```
2. **热路径选路优先级与安全兜底（Zero-Lock `ArcSwap`）**
   - 运行时权重存储在 `ArcSwap<Option<ManualWeightPolicy>>` 中，更新原子生效、请求热路径零锁竞争。
   - **选路优先级**：`1-Hop 防环（强制本地 UDS）` > `人工权重覆写（ManualWeightPolicy）` > `自动三段式水位溢出（Swarm P2C）` > `本机 UDS 默认直连`。
   - **长连接与会话保护**：权重调整**仅影响新建会话/流**；已建立的 HTTP/2 / XHTTP 长连接以及 `AffinityTable` 中尚未过期的 `/split/<session_id>` 会话继续保留在原节点直至自然结束。
   - **健康检查防黑洞（Fail-Safe）**：当人工指定权重的目标 Peer 在 Gossip 中变为 `Down` 时，自动跳过失效 Peer 并回退至其余健康 Peer 或本机 UDS，避免人工调权误造黑洞；若设置 `--ttl`（默认建议 `30m`），到期后自动清除覆写并恢复自动水位模式。
   - **重启/重载边界**：除首次部署外，后续配置更新统一采用 `fluxgate reload`（`ArcSwap` 热加载）而非 `restart`，且 `reload` 默认保留尚未过期的 `ManualWeightPolicy` 直至显式 `reset` 或 `TTL` 到期。
3. **与 HAProxy 异构节点及控制台页面联动**
   - 统一接入 `console.svc.plus/panel/ops/traffic-dispatch`（手动流量调度页）：运维可在同一界面观测节点引擎类型（`HAProxy` / `Fluxgate`）、活跃连接数（`scur` / `local_active_streams`），并按一致的 `80/20 -> 50/50 -> 20/80 -> 0/100` 节奏对 HAProxy 节点与 Fluxgate 蜂群节点执行排空、升级或慢节点应急切流。

#### 2.5.3 CLI 子命令增强

在 [src/cli.rs](file:///Users/shenlan/workspaces/fluxgate/src/cli.rs) 新增 `fluxgate swarm` 子命令集：
- `fluxgate swarm status`：输出本机负载分、水位状态、人工权重覆写状态（含剩余 TTL）、GTM Coordinator 身份、各节点当前 DNS 权重/灰度比例及蜂群成员表（各 Peer 的 `state`、`load_score`、`active_streams`、`rtt_ms`、`spillover_ratio`）。
- `fluxgate swarm weight set <local=W> <peer=W> [--ttl <duration>]` / `fluxgate swarm weight show` / `fluxgate swarm weight reset`：通过 `/run/fluxgate/admin.sock` 实时调整、查看或重置本机与对等节点的 L7 调度权重（零 `reload`、不断存量长连接）。
- `fluxgate swarm drain` / `fluxgate swarm resume`：通过本地控制接口将本节点置为 `Draining`（等价于 `local=0` 并将流量按健康度分给同群 Peer，同时触发 GTM Coordinator 将该节点 DNS 权重置 0 / 摘除 A 记录）或恢复为 `Alive`。

---

## 3. 代码模块落地映射

| 模块路径 | 变更类型 | 核心职责与实现设计 |
| :--- | :---: | :--- |
| [src/config/ast.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/ast.rs) | 修改 | 1. `GlobalConfig` 新增 `pub swarm: Option<SwarmConfig>`（内含 `pub gtm: Option<SwarmGtmConfig>`）；<br/>2. `ReverseProxyConfig` 新增 `pub swarm_spillover: Option<SwarmSpilloverConfig>`；<br/>3. `UpstreamTarget` 新增 `SwarmPeer { node_id: String, addr: String, sni: String }`。 |
| [src/config/parser.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/parser.rs) & [validate.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/validate.rs) | 修改 | 支持从 `/etc/fluxgate/conf.d/Swarm-Grouping-Mode.conf` 等 `import` 子文件中增量合并 `{ vault { ... } swarm { ... gtm { ... } } }` 全局块或直接解析顶层 `swarm { ... }`；校验水位关系与 `min_healthy_nodes >= 1`；在 `--strict-gitops` 下强制要求 `shared_key` 与 GTM DNS API 凭据使用 `{vault.*}` 或 `env(*)`。 |
| `src/swarm/mod.rs` | 新增 | `SwarmManager` 核心门面：整合 `LocalLoadEstimator`、`PeerTable`（`ArcSwap` 快照）、`AffinityTable` 与 P2C 选路器 `select_upstream()`。 |
| `src/swarm/score.rs` | 新增 | `LocalLoadEstimator`：聚合 `active_connections`、`/proc/self/statm` RSS、EWMA 延迟与本地 UDS 错误计数，每秒更新 `AtomicU8` `load_score`。 |
| `src/swarm/affinity.rs` | 新增 | 64 分片固定大小 `AffinityTable`（`< 256 KiB`），支持 URI `path_segment` 零拷贝提取与 SipHash 会话粘滞绑定。 |
| `src/swarm/gossip.rs` | 新增 | 实现 Pingora `BackgroundService`：定时执行 H2 `/_fluxgate/swarm/heartbeat` 并发探测、Gossip 成员合并、DNS SRV/A 记录发现与超时节点隔离。 |
| `src/swarm/admin_sock.rs` | 新增 | 实现本地 `/run/fluxgate/admin.sock` Unix Domain Socket 控制面（`set weight` / `reset weight` / `show stat` / `drain` / `resume`），通过 `ArcSwap<Option<ManualWeightPolicy>>` 支持零 `reload` 实时权重热调度与可选 TTL 自动过期恢复。 |
| `src/swarm/gtm.rs` | 新增 | 实现 ExternalDNS 自动注册与 GTM Coordinator `BackgroundService`：节点启动自动探测公网 IP 并 `upsert` 自身单机域名与发现记录（带 `_fluxgate-owner` TXT 所有权保护）；通过 Vault KV v2 CAS 选主驱动统一入口域名的动态健康池与灰度权重幂等对账。 |
| [src/acme/dns.rs](file:///Users/shenlan/workspaces/fluxgate/src/acme/dns.rs) | 扩展 | 抽象通用 `DnsRecordProvider` Trait，内置 `cloudflare`、`alidns`、`route53`、`dnspod` 四大主流规范 DNS 驱动，支持 `A`/`AAAA`/`SRV`/`TXT` 自动 `insert`/`upsert`/`delete`、所有权标记与权重 SLB 更新。 |
| `src/swarm/auth.rs` | 新增 | 基于 `hmac` + `sha2` 实现心跳与跨机溢出请求头 `X-Fluxgate-Swarm-Sig` 签名与时间窗校验。 |
| [src/proxy/service.rs](file:///Users/shenlan/workspaces/fluxgate/src/proxy/service.rs) | 修改 | 1. `request_filter()` 拦截 `/_fluxgate/swarm/heartbeat`；<br/>2. 识别 `X-Fluxgate-Swarm-Hop` 强制本地落地（1-Hop 防环）；<br/>3. 调用 `SwarmManager::select_upstream()` 决定走本机 UDS 或溢出至 Peer；<br/>4. `upstream_peer()` 为 `SwarmPeer` 构建 TLS + H2 多路复用 `HttpPeer`。 |
| [src/metrics.rs](file:///Users/shenlan/workspaces/fluxgate/src/metrics.rs) | 修改 | 扩展 `MetricsRegistry` 输出 `fluxgate_swarm_*` 与 `fluxgate_gtm_*` 系列 Prometheus 指标。 |

---

## 4. 分阶段实施路线（Milestones）

### M1：蜂群 DSL、多维负载分引擎与 1-Hop 防环路底座
- **交付内容**：
  - 完成 `swarm { ... gtm { ... } }` 与 `swarm_spillover {}` AST、Parser 及 `--strict-gitops` 校验单元测试；
  - 完成 `src/swarm/score.rs` 多维负载分计算与三段式水位状态机；
  - 完成 `src/swarm/auth.rs` HMAC 签名校验与 `X-Fluxgate-Swarm-Hop` 1-Hop 防环路拦截。
- **验收标准**：`cargo test` 覆盖所有水位边界、滞回防抖与非法签名/环路拒绝场景；未配置 `swarm` 时行为与 `v0.2.1` 100% 一致。

### M2：对等心跳 Gossip 自发现、本地 `admin.sock` 热调权与动态扩缩容
- **交付内容**：
  - 完成 `/_fluxgate/swarm/heartbeat` 端点与 `SwarmGossipService` (`BackgroundService`)；
  - 支持种子节点 Gossip 成员自动扩散、DNS 发现与 `Draining` 优雅排空状态广播；
  - 完成 `src/swarm/admin_sock.rs`（`/run/fluxgate/admin.sock` 支持 `set weight`、`reset weight`、`show stat` 与 `TTL` 过期自动回退）及 `fluxgate swarm status` / `weight` / `drain` / `resume` CLI。
- **验收标准**：本地启动 2 个 Fluxgate 实例（模拟 `jp-xconnect-plus-01`、`02`），随后动态启动第 3 个实例（`03`）仅指向 `01`，验证 `2s` 内 `01`、`02`、`03` 三方成员表自动收敛一致；通过 `admin.sock` 执行 `local=80/02=20 -> local=0/02=100` 验证零 `reload`、存量长连接不断、新建连接按权重切流且 `show stat` 准确反映 `scur` 归零；停止 `03` 后 `6s` 内自动摘除。

### M3：XHTTP 会话粘滞、Bounded-Load P2C 选路与本机故障 Failover
- **交付内容**：
  - 完成 `src/swarm/affinity.rs`（`/split/<session_id>` 提取与 64 分片固定内存粘滞表）；
  - 完成 P2C + `InFlightSpillover` 实时选路与 Pingora H2 TLS 跨机连接池转发；
  - 完成本机 UDS `fail_to_connect` 即时跨机 Failover。
- **验收标准**：
  - 模拟同一 `/split/<session_id>` 的并发 `POST` 与 `GET` 流，验证 100% 粘滞到同一目标节点；
  - 模拟单节点负载分升至 `90` 或断开本机 UDS，验证流量无损切往健康 Peer，且跨机请求数绝不发生二次转发（Hop 恒为 1）。

### M4：Vault KV + Cloudflare / 阿里云智能 DNS 轻量级 GTM 与灰度切流
- **交付内容**：
  - 扩展 [src/acme/dns.rs](file:///Users/shenlan/workspaces/fluxgate/src/acme/dns.rs) 支持 Cloudflare A/AAAA 动态池 & Paid LB Pool Weight API，以及阿里云 AliDNS 权重 SLB（`SetDNSSLBStatus` / `UpdateDNSSLBWeight`）与分线路解析 API；
  - 完成 `src/swarm/gtm.rs`：基于 Vault KV v2 CAS 选主、动态灰度权重（`canary_policy`）加载、过载节点自动摘除与 `min_healthy_nodes` 保底保护。
- **验收标准**：
  - 基于 Mock Cloudflare / AliDNS + Vault KV 测试验证：多节点并发运行时仅唯一 CAS Coordinator 发起 DNS 更新；
  - 当模拟 `01` 过载或 `drain` 时，Coordinator 自动将其 DNS 权重调降/摘除；修改 Vault KV 灰度配置（如 `03` 权重 `10% -> 50%`）后 `15s` 内自动同步至 Cloudflare / 阿里云 DNS。

### M5：Ansible Pull / GitOps 集成与东京 Plus 蜂群 500-VU K6 压测验收
- **交付内容**：
  - 更新 `ai-workspace-infra/playbooks/roles/vhosts/fluxgate` 模板支持 `fluxgate_swarm_enabled`、`fluxgate_gtm_enabled` 及蜂群参数渲染；
  - 在 `jp-xconnect-plus-01.svc.plus` 与 `jp-xconnect-plus-02.svc.plus` 上线 `jp-plus` 蜂群分组与 `jp-xconnect-plus.svc.plus` GTM 调度；
  - 补充 Grafana 蜂群拓扑、DNS GTM 权重与 L7 溢出流量面板。
- **验收标准**：
  - 单点向 `jp-xconnect-plus-01.svc.plus` 打入 `500 VUs` K6 极限压测流量，当 `01` 达到高水位后，L7 超额会话即时无感溢出至 `jp-xconnect-plus-02.svc.plus`，同时 L3 GTM 自动调整 `jp-xconnect-plus.svc.plus` 权重将后续新建客户端导向 `02`；
  - 压测全程可用性 **`100.00%`**，单机 `Fluxgate` 内存增幅 `< 10 MiB`（控制面开销 `< 2 MiB`），客户端零感知断流。
