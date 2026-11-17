# Fluxgate 🦀

[![CI](https://github.com/ai-workspace-xstream/fluxgate/actions/workflows/ci.yml/badge.svg)](https://github.com/ai-workspace-xstream/fluxgate/actions)
[![Language](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Engine](https://img.shields.io/badge/engine-Cloudflare_Pingora-blue.svg)](https://github.com/cloudflare/pingora)
[![DSL](https://img.shields.io/badge/syntax-Caddyfile_Compatible-00ADD8.svg)](https://caddyserver.com/)
[![License](https://img.shields.io/badge/license-Apache_2.0-green.svg)](LICENSE)

> **轻量级、零 GC 堆积、面向流式高并发的边缘反向代理。**  
> 基于 **Rust + Cloudflare Pingora** 工业级底座打造，原生兼容 **Caddyfile 声明式 DSL**。

![Fluxgate Benchmark Cover](docs/assets/fluxgate-benchmark-cover.jpg)

---

## 📖 诞生故事：从被 Go GC 逼疯到自研网关

在每月几刀的 1C1G 海外廉价小机上跑服务，很多运维和开发者都经历过这行刺眼的内核告警：
> `kernel: Out of memory: Killed process (caddy), rss: 225MB`

在资源充沛的大集群里，没人会在意几十兆内存；但在 1GB 内存的边缘小鸡上，扣除系统底噪和后端进程，留给反向代理的安全红线极其可怜。**在这里，每一兆常驻内存（RSS）都是生存权。**

* **Caddy 的甜与痛**：Caddyfile 语法极为丝滑，但在大吞吐的长流式转发下，Go Runtime 的内存分配与 GC 机制偏向吞吐优先，“只借不还”，常驻内存一路飙升到 **240MB+**，让整机天天在 OOM 边缘反复横跳；客户端断开连接还会刷爆 `Client closed H2` 伪告警。
* **HAProxy 的妥协**：纯 C 写的 HAProxy 3.0 内存控制确实克制（~64MB），但晦涩冗长、反人类的配置语法让日常维护心力交瘁。
* **AI 时代的觉醒**：**“造轮子而已，网络层的流式 CRUD 罢了。”** 只要上下文给足、Token 储备够充沛、愿意花时间打磨编译与内存细节，基于 Cloudflare 开源的 Rust Pingora，结合 Rust RAII 零运行时管理与 Caddyfile 语法兼容，高可用高性能专属网关根本不是大厂专属神话。

---

## 📊 生产多维硬核实测：负载之下见真章

> **技术真相：脱离负载谈内存，都是耍流氓！**

下图采集自多台 1 vCPU / 1 GB 内存海外边缘节点在实际生产流量下的 Grafana 统一看板监控：

![Fluxgate Grafana Dashboard](docs/assets/fluxgate-grafana-dashboard.jpg)

### 实测监控数据明细

| 边缘节点 (Instance) | 代理引擎 (Engine) | 实时吞吐 (QPS) | 活跃连接 (Active Conns) | 常驻内存 (RSS Memory) | CPU 占用率 | 运行状态与表现 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `jp-free-selfhost-prod-v2` | **HAProxy 3.0** (C Epoll) | 0.34 req/s | 3 | **79.1 MiB** | 0.02% | 内存平稳，但配置极其晦涩繁琐 |
| `jp-xconnect-01.svc.plus` | **Caddy 2.8+** (Go GC) | 0.10 req/s | 1 | **224.7 MiB** (红牌告警) | 0.24% | **高负载后内存只借不还，濒临 OOM 斩杀** |
| `jp-xconnect-02.svc.plus` | **Fluxgate 0.1.0** (Rust Pingora) | **5.38 ~ 6.59 req/s** | **89 ~ 101 conns** | **72.8 MiB** (全程绿标) | 1.82% | **顶着百倍吞吐与百级活跃长连接，内存依旧稳如磐石** |
| `ph-xconnect.svc.plus` | Caddy (Go GC) | 0.00 req/s | 0 | 25.9 MiB | 0.05% | 专属低频节点（空载时各引擎均温顺） |
| `us-xconnect-los-angeles` | Caddy (Go GC) | 0.40 req/s | 0 | 34.2 MiB | 0.16% | 专属低频节点（空载时各引擎均温顺） |
| `us-xconnect.svc.plus` | Caddy (Go GC) | 0.20 req/s | 0 | 32.7 MiB | 0.24% | 专属低频节点（空载时各引擎均温顺） |

### 关键战报结论
1. **低负载无差别**：在 0 吞吐的专属低频节点上，Caddy 也能保持在 25~34 MiB；
2. **高负载见分晓**：一旦进入长流真实高吞吐战场，Caddy 的 Go Runtime 堆膨胀被彻底锁死在 **225 MB+**；而 **Fluxgate 哪怕扛着 101 个活跃长连接、60 倍以上吞吐，常驻内存仍只有 72.8 MiB**（空载冷启动仅 **5.1 MiB**），彻底粉碎 1GB 小机的 OOM 焦虑！

---

## ⚡ 核心架构与技术特性

- **Cloudflare Pingora 工业底座 (`pingora 0.9.1`)**：基于多线程异步 Tokio 运行时，Rust RAII 严格管理内存生命周期，零 GC STW 停顿，彻底消除内存毛刺。
- **100% Caddyfile 核心语法兼容**：直接复用熟悉优雅的 Caddyfile，零学习与零迁移成本原地平替。
- **原生 `h2c` over Unix Domain Socket**：显式保持 HTTP/2 cleartext prior-knowledge 转发给本地 UDS（如 `/dev/shm/xray.sock`），杜绝隐式降级至 HTTP/1.1。
- **纯净日志 • 源码级 499 降噪**：拦截下游客户端主动发起的 `RST_STREAM` / `stream no longer needed` 取消事件，智能映射为 HTTP 499，彻底平息伪报警刷屏。
- **流式零缓冲流水线**：流式透传双向 Body 数据流，默认配置 1MB HTTP/2 流控大窗口，禁用不安全的自动重试机制。

---

## 🛠️ 快速上手

### 命令行使用

```bash
# 校验配置文件语法（支持友好报错与行号定位）
fluxgate validate --config /etc/fluxgate/Fluxgatefile

# 启动反向代理服务
fluxgate run --config /etc/fluxgate/Fluxgatefile

# 查看版本
fluxgate version
```

### 配置示例 (`Fluxgatefile`)

Fluxgate 原生支持 Caddyfile 核心 DSL，以前怎么写，现在照样跑：

```caddy
{
    grace_period 15s
    log {
        level INFO
    }
}

import /etc/fluxgate/conf.d/*.conf
```

站点子配置示例 (`conf.d/jp-xconnect-02.conf`)：

```caddy
jp-xconnect-02.svc.plus {
    tls /etc/fluxgate/tls/server.crt /etc/fluxgate/tls/server.key

    @stream {
        path /split /split/*
    }
    rewrite @stream /split/

    handle @stream {
        uri query -x_padding

        reverse_proxy unix//dev/shm/xray.sock {
            flush_interval -1
            transport http {
                versions h2c 2
            }
        }
    }

    handle_path /exporter/* {
        reverse_proxy 127.0.0.1:8080
    }

    respond "Fluxgate Edge Node Ready" 200
}
```

---

## 📋 Caddyfile 语法兼容矩阵

Fluxgate 精准聚焦高频核心 DSL，杜绝冗余：

| 指令 / 语法特性 | 支持状态 | 说明 |
| :--- | :---: | :--- |
| 全局块 `{ grace_period ...; log { ... } }` | ✅ 支持 | 映射为 Pingora `grace_period_seconds` 与 Tokio 日志过滤器 |
| `import <glob/path>` | ✅ 支持 | 支持相对/绝对路径、排序通配符、循环引用与深度 (`16`) 检测 |
| 站点块 `<domain1> <domain2> { ... }` | ✅ 支持 | 支持精确域名与通配符 (`*.domain`) 匹配 |
| `tls <cert> <key>` | ✅ 支持 | OpenSSL 现代化加密套件，支持 H2 / HTTP/1.1 ALPN 协商 |
| `handle_path <prefix> { ... }` | ✅ 支持 | 前缀剥离并隔离路由处理 |
| `@name { path ... }` / `@name path ...` | ✅ 支持 | 具名路径匹配器（精确匹配与 `*` 通配） |
| `handle [@matcher] { ... }` | ✅ 支持 | 互斥路由分支执行器 |
| `rewrite [@matcher] <target>` | ✅ 支持 | 请求路径与 URI 内部重写 |
| `uri query -<param>` | ✅ 支持 | 动态清洗指定 Query 参数，保留其余合法参数 |
| `reverse_proxy <tcp\|unix//...> { ... }` | ✅ 支持 | 支持 `flush_interval -1` 与 `versions h2c 2` 零拷贝管道 |
| `respond "<body>" [status]` | ✅ 支持 | 高性能静态降级与健康检查响应 |
| 未知或未实现指令 | 🛑 严格拒绝 | 启动或检验阶段直接明确定位行号并拦截，杜绝隐式故障 |

---

## 🚀 部署与零风险平滑回滚

Fluxgate 采用纯静态交叉编译二进制交付，生产节点无需安装任何 Rust 工具链：

```bash
# 1. 验证配置
fluxgate validate --config /etc/fluxgate/Fluxgatefile

# 2. 从 Caddy/HAProxy 切换至 Fluxgate（现有 Caddyfile 配置完全保留）
sudo systemctl disable --now caddy haproxy 2>/dev/null || true
sudo systemctl enable --now fluxgate

# 3. 极速秒级回滚（若遇突发状况）
sudo systemctl disable --now fluxgate
sudo systemctl enable --now caddy   # 或 haproxy
```

---

## 🤝 致敬与开源理念

> **“只要 Token 足够，打磨时间足够，一切皆有可能。”**

- 底层网络引擎致敬 [Cloudflare Pingora](https://github.com/cloudflare/pingora) 项目。
- 配置哲学致敬 [Caddy Server](https://github.com/caddyserver/caddy) 优雅的 Caddyfile 设计。
- 欢迎提交 Issue、PR 或分享你在轻量边缘服务器上的优化实录！
