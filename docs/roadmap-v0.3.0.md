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
4. **严守 1 GiB 边缘节点资源红线**
   - 延续单二进制极简形态：蜂群心跳、Gossip 成员管理、负载评分与会话粘滞表全部运行在现有 Pingora `BackgroundService` 与 Tokio Runtime 内，不引入 Consul / Etcd / Redis 等任何外部组件。
   - **内存预算**：蜂群控制面与固定容量分片会话粘滞表（`AffinityTable`）新增常驻内存严格控制在 **`< 2 MiB`**；请求热路径全面采用 `ArcSwap` 与原子指令，零全局互斥锁阻塞。

### 1.2 总体架构

```
                  客户端流量 (XConnect / VLESS-XHTTP / H2)
                     │                               │
       ┌─────────────▼─────────────┐   ┌─────────────▼─────────────┐
       │ jp-xconnect-plus-01       │   │ jp-xconnect-plus-02       │
       │ Fluxgate v0.3 (Load: 88%) │   │ Fluxgate v0.3 (Load: 25%) │
       ├───────────────────────────┤   ├───────────────────────────┤
       │ 1. 水位 <=75%: 本机 UDS    │   │ 接收直连 + 01 溢出流量     │
       │    /dev/shm/xray.sock     │   │ (X-Fluxgate-Swarm-Hop: 1  │
       │ 2. 水位 >75%: 新会话粘滞   │   │  强制本机 UDS 落地，防环)  │
       │    P2C 选路 ──────────────┼───► /dev/shm/xray.sock        │
       └─────────────▲─────────────┘   └─────────────▲─────────────┘
                     │  /_fluxgate/swarm/heartbeat   │
                     │  (H2 2s 轻量级指标与成员 Gossip)│
                     └───────────────┬───────────────┘
                                     ▼
                     ┌───────────────────────────────┐
                     │ jp-xconnect-plus-03 ... -0N   │
                     │ (配置同一 group & seed 即可   │
                     │  随时自由加入/退出蜂群)        │
                     └───────────────────────────────┘
```

---

## 2. 特性详细设计

### 特性 1：蜂群分组 DSL 与去中心化动态节点发现

**目标**：在不破坏 Caddyfile 声明式体验的前提下，让同区域多节点（`jp-xconnect-plus-01`、`jp-xconnect-plus-02` 及后续新节点）使用统一的配置模板即可组成自治蜂群。

#### 2.1.1 DSL 声明规范

在全局块 `{ ... }` 新增 `swarm { ... }` 配置块，并在站点 `reverse_proxy` 块内新增 `swarm_spillover { ... }` 策略：

```caddy
{
    grace_period 15s
    metrics 127.0.0.1:9102

    vault {
        addr env(VAULT_ADDR)
        auth approle
        sync swarm kv/data/prod/fluxgate/swarm 5m
    }

    # Fluxgate v0.3 蜂群分组全局配置
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
    }
}

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
            # 蜂群无感分流策略
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

### 特性 4：可观测性、CLI 诊断与 GitOps 联动

#### 2.4.1 Prometheus 监控指标（`/metrics`）

在 [src/metrics.rs](file:///Users/shenlan/workspaces/fluxgate/src/metrics.rs) 新增以下蜂群专属指标：
- `fluxgate_swarm_load_score{group="jp-plus",node_id="..."}`（Gauge `0~100`：本机实时综合负载分）
- `fluxgate_swarm_peers_total{group="jp-plus",state="alive|suspect|draining|down"}`（Gauge：蜂群各状态节点数）
- `fluxgate_swarm_peer_load_score{group="jp-plus",peer="jp-xconnect-plus-02.svc.plus"}`（Gauge：本机视角下各对等节点的负载分）
- `fluxgate_swarm_peer_rtt_seconds{group="jp-plus",peer="..."}`（Gauge：与各对等节点的心跳 RTT）
- `fluxgate_swarm_decisions_total{group="jp-plus",decision="local|spillover|failover|forced_local_hop"}`（Counter：选路决策分布）
- `fluxgate_swarm_spillover_requests_total{group="jp-plus",target_peer="..."}`（Counter：溢出至各 Peer 的请求数）
- `fluxgate_swarm_spillover_active_streams{group="jp-plus",target_peer="..."}`（Gauge：当前正溢出至各 Peer 的并发流数）

#### 2.4.2 CLI 子命令增强

在 [src/cli.rs](file:///Users/shenlan/workspaces/fluxgate/src/cli.rs) 新增 `fluxgate swarm` 子命令集：
- `fluxgate swarm status`：输出本机负载分、水位状态及蜂群成员表（各 Peer 的 `state`、`load_score`、`active_streams`、`rtt_ms`、`spillover_ratio`）。
- `fluxgate swarm drain` / `fluxgate swarm resume`：通过本地控制接口或信号将本节点置为 `Draining`（平滑排空流量以进行维护）或恢复为 `Alive`。

---

## 3. 代码模块落地映射

| 模块路径 | 变更类型 | 核心职责与实现设计 |
| :--- | :---: | :--- |
| [src/config/ast.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/ast.rs) | 修改 | 1. `GlobalConfig` 新增 `pub swarm: Option<SwarmConfig>`；<br/>2. `ReverseProxyConfig` 新增 `pub swarm_spillover: Option<SwarmSpilloverConfig>`；<br/>3. `UpstreamTarget` 新增 `SwarmPeer { node_id: String, addr: String, sni: String }`。 |
| [src/config/parser.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/parser.rs) & [validate.rs](file:///Users/shenlan/workspaces/fluxgate/src/config/validate.rs) | 修改 | 解析 `swarm { ... }` 与 `swarm_spillover { ... }`；校验 `low_watermark < high_watermark <= 100`；在 `--strict-gitops` 下强制要求 `shared_key` 使用 `{vault.*}` 或 `env(*)`，拒绝明文密钥。 |
| `src/swarm/mod.rs` | 新增 | `SwarmManager` 核心门面：整合 `LocalLoadEstimator`、`PeerTable`（`ArcSwap` 快照）、`AffinityTable` 与 P2C 选路器 `select_upstream()`。 |
| `src/swarm/score.rs` | 新增 | `LocalLoadEstimator`：聚合 `active_connections`、`/proc/self/statm` RSS、EWMA 延迟与本地 UDS 错误计数，每秒更新 `AtomicU8` `load_score`。 |
| `src/swarm/affinity.rs` | 新增 | 64 分片固定大小 `AffinityTable`（`< 256 KiB`），支持 URI `path_segment` 零拷贝提取与 SipHash 会话粘滞绑定。 |
| `src/swarm/gossip.rs` | 新增 | 实现 Pingora `BackgroundService`：定时执行 H2 `/_fluxgate/swarm/heartbeat` 并发探测、Gossip 成员合并、DNS SRV/A 记录发现与超时节点隔离。 |
| `src/swarm/auth.rs` | 新增 | 基于 `hmac` + `sha2`（或 OpenSSL HMAC）实现心跳与跨机溢出请求头 `X-Fluxgate-Swarm-Sig` 签名与时间窗校验。 |
| [src/proxy/service.rs](file:///Users/shenlan/workspaces/fluxgate/src/proxy/service.rs) | 修改 | 1. `request_filter()` 拦截 `/_fluxgate/swarm/heartbeat`；<br/>2. 识别 `X-Fluxgate-Swarm-Hop` 强制本地落地（1-Hop 防环）；<br/>3. 调用 `SwarmManager::select_upstream()` 决定走本机 UDS 或溢出至 Peer；<br/>4. `upstream_peer()` 为 `SwarmPeer` 构建 TLS + H2 多路复用 `HttpPeer`。 |
| [src/metrics.rs](file:///Users/shenlan/workspaces/fluxgate/src/metrics.rs) | 修改 | 扩展 `MetricsRegistry` 输出 `fluxgate_swarm_*` 系列 Prometheus 指标。 |

---

## 4. 分阶段实施路线（Milestones）

### M1：蜂群 DSL、多维负载分引擎与 1-Hop 防环路底座
- **交付内容**：
  - 完成 `swarm {}` 与 `swarm_spillover {}` AST、Parser 及 `--strict-gitops` 校验单元测试；
  - 完成 `src/swarm/score.rs` 多维负载分计算与三段式水位状态机；
  - 完成 `src/swarm/auth.rs` HMAC 签名校验与 `X-Fluxgate-Swarm-Hop` 1-Hop 防环路拦截。
- **验收标准**：`cargo test` 覆盖所有水位边界、滞回防抖与非法签名/环路拒绝场景；未配置 `swarm` 时行为与 `v0.2.1` 100% 一致。

### M2：对等心跳 Gossip 自发现与动态扩缩容
- **交付内容**：
  - 完成 `/_fluxgate/swarm/heartbeat` 端点与 `SwarmGossipService` (`BackgroundService`)；
  - 支持种子节点 Gossip 成员自动扩散、DNS 发现与 `Draining` 优雅排空状态广播；
  - 完成 `fluxgate swarm status` / `drain` CLI。
- **验收标准**：本地启动 2 个 Fluxgate 实例（模拟 `jp-xconnect-plus-01`、`02`），随后动态启动第 3 个实例（`03`）仅指向 `01`，验证 `2s` 内 `01`、`02`、`03` 三方成员表自动收敛一致；停止 `03` 后 `6s` 内自动摘除。

### M3：XHTTP 会话粘滞、Bounded-Load P2C 选路与本机故障 Failover
- **交付内容**：
  - 完成 `src/swarm/affinity.rs`（`/split/<session_id>` 提取与 64 分片固定内存粘滞表）；
  - 完成 P2C + `InFlightSpillover` 实时选路与 Pingora H2 TLS 跨机连接池转发；
  - 完成本机 UDS `fail_to_connect` 即时跨机 Failover。
- **验收标准**：
  - 模拟同一 `/split/<session_id>` 的并发 `POST` 与 `GET` 流，验证 100% 粘滞到同一目标节点；
  - 模拟单节点负载分升至 `90` 或断开本机 UDS，验证流量无损切往健康 Peer，且跨机请求数绝不发生二次转发（Hop 恒为 1）。

### M4：Ansible Pull / GitOps 集成与东京 Plus 蜂群 500-VU K6 压测验收
- **交付内容**：
  - 更新 `ai-workspace-infra/playbooks/roles/vhosts/fluxgate` 模板支持 `fluxgate_swarm_enabled` 及蜂群参数渲染；
  - 在 `jp-xconnect-plus-01.svc.plus` 与 `jp-xconnect-plus-02.svc.plus` 上线 `jp-plus` 蜂群分组；
  - 补充 Grafana 蜂群拓扑与溢出流量面板。
- **验收标准**：
  - 单点向 `jp-xconnect-plus-01.svc.plus` 打入 `500 VUs` K6 极限压测流量，当 `01` 达到高水位后，超额会话自动无感溢出至 `jp-xconnect-plus-02.svc.plus`；
  - 压测全程可用性 **`100.00%`**，单机 `Fluxgate` 内存增幅 `< 10 MiB`（控制面开销 `< 2 MiB`），客户端零感知断流。
