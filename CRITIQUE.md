# Mirage 项目深度批判性分析

> 基于源码审计 + 2024-2025 学术前沿研究的系统性评估
> 分析日期: 2026-04-07

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [架构概述与设计意图](#2-架构概述与设计意图)
3. [致命缺陷：TLS-in-TLS 指纹泄露](#3-致命缺陷tls-in-tls-指纹泄露)
4. [严重缺陷：跨层 RTT 不一致](#4-严重缺陷跨层-rtt-不一致)
5. [协议层面的结构性弱点](#5-协议层面的结构性弱点)
6. [流量形态学缺陷](#6-流量形态学缺陷)
7. [密码学与认证机制问题](#7-密码学与认证机制问题)
8. [工程实现层面的问题](#8-工程实现层面的问题)
9. [CDN 依赖的战略性风险](#9-cdn-依赖的战略性风险)
10. [与同类工具的比较分析](#10-与同类工具的比较分析)
11. [改良建议与路线图](#11-改良建议与路线图)
12. [参考文献](#12-参考文献)

---

## 1. 执行摘要

Mirage 是一个基于 "Turbo Tunnel" 理念的反审查代理协议，采用 QUIC-in-HTTP/2-over-Cloudflare 三层封装架构。项目设计思路清晰，工程实现简洁（约 2000 行 Go 代码），在 CDN 前置、uTLS 指纹伪装、指数衰减 padding 等方面做了有价值的尝试。

然而，经过与 2024-2025 年最新学术研究的交叉比对，**项目存在多个从根本架构层面难以修补的安全缺陷**。其中最致命的是：

| 威胁等级 | 缺陷 | 学术依据 |
|---------|------|---------|
| **致命** | TLS-in-TLS 封装指纹可被协议无关地检测 | USENIX Security 2024 [1] |
| **致命** | 跨层 RTT 差异暴露代理拓扑 | NDSS 2025 [2] |
| **严重** | Morph 模块实际未被集成到数据通路 | 源码审计 |
| **严重** | uTLS 库级指纹伪装已被行业质疑 | sing-box 官方警告 [3] |
| **高** | 内层 QUIC 引入不必要的复杂性和开销 | 架构分析 |
| **高** | PSK 密钥派生无 KDF 拉伸 | 密码学审计 |

**结论**：Mirage 当前设计无法抵御 USENIX Security 2024 和 NDSS 2025 描述的检测方法。需要根本性的架构重构，而非参数调优。

---

## 2. 架构概述与设计意图

### 2.1 协议栈

```
┌─────────────────────────────────────┐
│  用户应用 (SOCKS5)                    │
├─────────────────────────────────────┤
│  自定义 Mux (7字节帧头)               │  ← 流多路复用
├─────────────────────────────────────┤
│  内层 QUIC (quic-go, 用户态)          │  ← 可靠传输 + 会话恢复
├─────────────────────────────────────┤
│  HTTP/2 Carrier (POST上行/GET下行)    │  ← 序列化传输
├─────────────────────────────────────┤
│  uTLS (Chrome JA3/JA4)              │  ← TLS 指纹伪装
├─────────────────────────────────────┤
│  Cloudflare CDN (外层 TLS 1.3)       │  ← CDN 前置
└─────────────────────────────────────┘
```

### 2.2 设计意图的合理性

项目明确瞄准了审查的多个检测维度：

- **IP/SNI 封锁** → CDN 前置（合理）
- **TLS 指纹** → uTLS Chrome 伪装（思路对，实现有问题）
- **主动探测** → 真实网站 + JSON 错误响应（有效）
- **流量模式** → 指数衰减 padding（思路创新但未集成）
- **会话恢复** → Turbo Tunnel / QUIC 会话持久化（过度工程）

---

## 3. 致命缺陷：TLS-in-TLS 指纹泄露

### 3.1 学术背景

**"Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes"** (Xue et al., USENIX Security 2024) [1] 是 2024 年代理检测领域最重要的论文。其核心发现：

> 当用户通过加密隧道访问 HTTPS 网站时，内层 TLS 握手会在外层加密流中产生**协议无关的、可靠可检测的指纹**。即使外层协议使用了随机 padding、多层封装、流多路复用，这种指纹仍然存在。

检测原理：

```
正常 HTTPS 连接:
  Client → [TLS ClientHello] → Server → [TLS ServerHello + Cert] → ...

通过 Mirage 的连接:
  Client → [外层 TLS(CDN)] → CDN → [HTTP/2 POST(Mux(QUIC(内层 TLS ClientHello)))] → Origin
                                                         ↑
                                            这个内层握手的大小/时序模式可被检测
```

### 3.2 Mirage 为何无法免疫

Mirage 的三层封装（TLS → HTTP/2 → Mux）并不能消除 TLS-in-TLS 指纹，因为：

1. **包大小特征保留**：当用户访问 `https://google.com` 时，内层 TLS ClientHello (~517 bytes) 会被 Mux 封装为 `[cmd:1][streamID:4][length:2][517 bytes ClientHello]` = 524 bytes。这个大小通过 HTTP/2 DATA frame 传输，虽然外层加密了，但 **长度信息在 TLS record 层可观察**。

2. **时序特征保留**：TLS 握手是 request-response 模式（ClientHello → ServerHello → ...），这种交替模式在 Mux 流中仍然可见。每次用户打开新的 HTTPS 连接，都会在 Mirage 隧道中产生一个新的 Mux 流，其前几个包的大小和方向完美匹配 TLS 握手签名。

3. **论文已验证此类架构无效**：论文的实验对象包括多种流多路复用代理（包括与 Mirage 架构相似的工具），检测率仍然极高。论文明确指出：

> "Stream multiplexing shows promise as a countermeasure but **existing implementations are insufficient**."

### 3.3 当前 Mirage 代码中的问题

```go
// internal/client/client.go — 每个 SOCKS5 连接开一个新 Mux stream
func (c *Client) handleConn(conn net.Conn) {
    st, _ := c.muxSess.OpenStream()  // → CmdSYN 帧
    // 写入目标地址
    st.Write(targetBytes)             // → CmdPSH 帧 (小包: 目标地址)
    relay.Bidirectional(conn, st)     // → 内层 TLS 握手的包在这里传递
}
```

每个新流的前几个 CmdPSH 帧会精确反映内层 TLS 握手的大小和方向。审查者不需要解密外层 TLS，只需观察 TLS record 大小序列即可检测。

### 3.4 严重性评估

- **检测率**：论文在真实 ISP（100万+ 用户）中部署，检测准确率 > 95%
- **协议无关**：不针对特定代理协议，而是检测所有封装 TLS 的代理流量
- **无法通过参数调优修复**：这是架构层面的根本问题
- **CDN 不能挡住**：Cloudflare 终止外层 TLS 后重新加密到 origin，但 ISP 侧看到的是 client → CDN 的流量，TLS record 大小仍然泄露内层握手模式

---

## 4. 严重缺陷：跨层 RTT 不一致

### 4.1 学术背景

**"The Discriminative Power of Cross-layer RTTs in Fingerprinting Proxy Traffic"** (Xue et al., NDSS 2025) [2] 揭示了代理流量的另一个固有指纹：

> 代理通信中，传输层会话在代理处断开（client↔proxy, proxy↔server），但应用层会话保持端到端。这导致传输层 RTT 与应用层 RTT 之间存在**可测量的不一致**。

### 4.2 对 Mirage 的影响

```
传输层 RTT: Client ←→ Cloudflare CDN (e.g., 20ms)
应用层 RTT: Client ←→ Destination (e.g., 200ms, 经 CDN → Origin → Destination)
```

虽然 Mirage 的 README 声称 "CDN 终止两端 TCP 和 TLS，审查者无法测量端到端 RTT"，但 NDSS 2025 的方法不依赖直接 RTT 测量：

- 通过观察 **HTTP/2 流中 request-response 的时间间隔**，可以推断应用层 RTT
- 与 **TCP ACK 的 RTT**（反映 client → CDN）对比，差异显著
- CDN 引入的额外延迟（CDN → Origin → Destination → Origin → CDN）使这种差异更加明显

### 4.3 严重性评估

- **协议无关**：不针对特定代理协议
- **CDN 加剧问题**：CDN 引入的多跳延迟使跨层 RTT 差异更大，反而更容易检测
- **被动检测**：无需主动探测，纯流量分析即可

---

## 5. 协议层面的结构性弱点

### 5.1 内层 QUIC 的过度工程

**问题**：Mirage 在 HTTP/2（已提供可靠有序传输）之上运行了一个完整的 QUIC 协议栈。但在最新版本中（commit `5b4b858`），内层 QUIC 已被替换为简单 frame mux（获得 25x 速度提升）。这说明开发者已意识到 QUIC 是不必要的。

然而，代码中仍保留了完整的 `internal/session/` 包（`client.go`, `server.go`, `memconn.go`），且 `go.mod` 仍依赖 `quic-go v0.59.0`。这意味着：

1. **依赖面过大**：`quic-go` 引入大量间接依赖，增加供应链攻击面
2. **二进制体积**：未使用的 QUIC 代码仍被编译进二进制
3. **代码混淆**：维护者和审计者难以确定哪条代码路径是活跃的

### 5.2 Mux 协议缺乏流控

当前 Mux 实现（`internal/mux/mux.go`）没有流控机制：

```go
// mux.go:218 — 缓冲区满时直接丢包
func (st *Stream) pushData(data []byte) {
    select {
    case st.readBuf <- data:
    default:
        log.Printf("mux: stream %d buffer full, dropping", st.id)
    }
}
```

问题：
- **静默数据丢失**：缓冲区满（64 slots）时数据被丢弃，仅打印日志
- **无背压传播**：发送方无法感知接收方的处理能力
- **高吞吐场景下可靠性存疑**：下载大文件时，如果代理端处理慢于客户端发送，数据会丢失
- **与 "可靠传输" 的设计目标矛盾**

### 5.3 Stream ID 空间耗尽

```go
// mux.go:53 — Stream ID 使用 atomic uint32 递增
func (s *Session) OpenStream() (*Stream, error) {
    id := s.nextID.Add(1)  // 永远递增，不回收
    ...
}
```

- uint32 最大值 ~4.3 billion，实际使用中不太可能溢出
- 但 **ID 回绕后会与已有流冲突**，无任何检测或保护机制
- 更重要的是，`streams` map 在长时间运行后可能因未正确清理而内存泄漏

### 5.4 半关闭语义不完整

```go
// mux.go:209 — Close 仅发送 FIN，不等待对端确认
func (st *Stream) Close() error {
    if st.closed.Swap(true) {
        return nil
    }
    st.sess.writeFrame(CmdFIN, st.id, nil)
    st.sess.removeStream(st.id)
    return nil
}
```

- 没有 TCP 式的 FIN-ACK 交互
- 发送 FIN 后立即从 map 中删除，如果对端还有数据在途，这些数据会被丢弃
- 可能导致连接被代理的应用出现随机数据截断

---

## 6. 流量形态学缺陷

### 6.1 Morph 模块未集成（最严重的遗漏）

**这是整个项目中最令人困惑的问题**。`internal/morph/morph.go` 实现了一个精心设计的指数衰减 padding 系统，包含 Chrome HTTP/2 帧大小分布、抖动延迟等。但是：

```bash
# 在整个项目中搜索 morph 包的引用
$ grep -r "morph" --include="*.go" internal/ cmd/
# 结果: 仅 morph/ 目录自身的文件和测试文件
```

**Morph 模块从未被任何其他包导入或调用。** 这意味着：

- 宣传的 "指数衰减 padding" **实际未生效**
- 宣传的 "Chrome HTTP/2 帧大小分布模拟" **实际未生效**
- 宣传的 "抖动延迟" **实际未生效**
- 项目的流量模式就是**裸 HTTP/2 POST/GET**，没有任何形态伪装

这使得 Mirage 的流量在统计上与正常的 HTTP/2 视频流截然不同：
- 正常视频流：下行远大于上行，包大小分布集中在大包
- Mirage 代理流量：上下行比例取决于用户行为，包大小分布与网页浏览特征一致

### 6.2 Keepalive Padding 不足

服务端确实实现了 keepalive padding（`carrier/server.go`），但：

```go
// carrier/server.go — 每 5s 发 64-192 字节随机数据
keepalive := time.NewTicker(5 * time.Second)
// ...
pad := make([]byte, 64+rand.Intn(129))
```

问题：
- **仅在 GET 下行方向**：POST 上行没有 padding
- **间隔固定 5s**：这本身就是一个可检测的特征（真实视频流的缓冲请求间隔是高度可变的）
- **大小范围太窄**：64-192 字节，真实视频流的 chunk 大小变化幅度大得多（1KB-1MB+）

### 6.3 Fragment 层未集成

`internal/fragment/outer.go` 实现了 TLS ClientHello 分片（用于绕过 SNI-based DPI），但同样**未被集成到主代码路径**。由于 Mirage 使用 CDN 前置，SNI 指向的是 CDN 域名（不在黑名单上），ClientHello 分片实际上也不需要。但这说明代码库中存在多个"孤岛"模块。

### 6.4 视频伪装的脆弱性

```go
// server.go:144 — 设置 Content-Type: video/mp4
w.Header().Set("Content-Type", "video/mp4")
```

通过 CDN 传输时，Cloudflare 会看到这个 Content-Type。但问题是：

- **没有 Range 请求**：真实视频流使用 HTTP Range 请求逐段加载，Mirage 使用单个长连接流
- **没有 .mp4 moov atom**：响应体内容是 Mux 帧，不是 MP4 容器格式
- **Cloudflare 的 ML 系统可能标记异常**：CDN 内部可以看到明文 HTTP，Content-Type 声称 video/mp4 但内容完全不像视频
- **无 Content-Length**：视频通常有明确长度或使用标准分段传输

---

## 7. 密码学与认证机制问题

### 7.1 PSK 密钥派生无拉伸

```go
// auth/token.go:23 — 直接 SHA256(PSK)
func New(psk string) *Auth {
    key := sha256.Sum256([]byte(psk))
    ...
}
```

**问题**：
- SHA256 是快速哈希，不适合密码派生
- 用户可能选择弱 PSK（如 "password123"），SHA256 无法提供对暴力破解的保护
- **应使用** Argon2id、scrypt 或至少 PBKDF2 进行密钥拉伸

### 7.2 Nonce 重放检测的内存泄漏风险

```go
// auth/token.go:111 — cleanup 每 60s 运行一次
func (a *Auth) cleanupLoop() {
    ticker := time.NewTicker(60 * time.Second)
    for range ticker.C {
        a.mu.Lock()
        for k, exp := range a.seen {
            if now.After(exp) { delete(a.seen, k) }
        }
        a.mu.Unlock()
    }
}
```

- 在高并发下（每个 POST 和 GET 都生成新 token），`seen` map 增长迅速
- 每个 token 的 nonce 占用 12 bytes key + 24 bytes time.Time value = 36 bytes，外加 map 开销
- 1000 req/s × 60s cleanup interval = 60,000 entries ≈ 数 MB，可控但无上限保护
- **缺少最大容量限制**：恶意客户端可通过大量无效请求（仍需解密验证）耗尽内存

### 7.3 UserID 固定为 1

```go
// carrier/client.go:97 — userID 硬编码为 1
func (c *ClientCarrier) freshToken() string {
    t, _ := c.auth.Generate(1, c.sessionID)  // userID 永远是 1
    return t
}
```

- 多用户支持形同虚设
- 无法区分不同用户的流量配额、权限
- 如果 PSK 泄露，所有用户一起暴露

### 7.4 错误处理不区分认证失败类型

```go
// server.go:122 — 所有认证失败返回相同的 401
_, sessionID, err := s.auth.Validate(...)
if err != nil {
    s.apiError(w, 401)
    return
}
```

虽然统一错误响应是好的安全实践（避免信息泄露），但内部缺少对不同失败类型的监控：
- 无法区分 "token 过期" vs "PSK 错误" vs "重放攻击"
- 无法实现速率限制或自动封禁

---

## 8. 工程实现层面的问题

### 8.1 无优雅退出机制

```go
// cmd/mirage-server/main.go — 直接 log.Fatal
if err := srv.Run(); err != nil {
    log.Fatal(err)
}
```

- 没有信号处理（SIGTERM, SIGINT）
- 没有连接排空（graceful drain）
- 活跃的代理连接会被强制中断
- `cleanupLoop` 的 goroutine 会泄漏（没有 context 或 done channel）

### 8.2 日志泄露敏感信息

```go
// server.go:192 — 打印目标地址
log.Printf("proxy: %s", target)
```

- 代理目标（用户访问的网站）被打印到标准日志
- 在某些司法管辖区，服务器运营者可能被要求提供日志
- 应至少提供选项来禁用目标地址日志

### 8.3 缺少健康检查和监控

- 无 metrics 导出（Prometheus 等）
- 无法观测当前活跃连接数、流量吞吐、错误率
- 无 session 超时清理（如果客户端异常断开，`sessions` map 中的 entry 可能永远不会被清理）

### 8.4 并发安全问题

```go
// server.go:73 — getOrCreateSession 有竞态条件
func (s *Server) getOrCreateSession(sessionID []byte) *serverSession {
    key := string(sessionID)
    s.mu.Lock()
    ss, exists := s.sessions[key]
    if exists {
        s.mu.Unlock()  // ← 释放锁后，ss 可能被其他 goroutine 关闭
        return ss
    }
    // ... 创建新 session ...
}
```

虽然概率低，但在 session 刚被创建后、RecvLoop goroutine 失败导致 session 被清理时，如果恰好有新的 POST/GET 进来，可能会写入已关闭的 pipe。

### 8.5 错误吞没

```go
// carrier/client.go:97 — 忽略 Generate 错误
func (c *ClientCarrier) freshToken() string {
    t, _ := c.auth.Generate(1, c.sessionID)  // 忽略 error
    return t
}
```

如果系统随机数源耗尽（虽然极罕见），token 生成会静默失败，发送空 Authorization header。

---

## 9. CDN 依赖的战略性风险

### 9.1 Cloudflare 的合规风险

- **Domain fronting 已被 Cloudflare 禁止**（2015年起）：Mirage 使用的是合法域名直连（非 domain fronting），但 Cloudflare 的 TOS 可能禁止将 CDN 用于代理/VPN 服务
- **Cloudflare 可以看到明文 HTTP**：在 CDN 边缘终止 TLS 后，Cloudflare 可以看到 POST 到 `/api/v2/tunnel` 的流量模式
- **大规模使用会被注意**：如果 Mirage 变得流行，Cloudflare 可能主动配合审查方封禁

### 9.2 ECH 的双刃剑

Cloudflare 于 2024 年 8 月部署了 Encrypted Client Hello (ECH)。根据 FOCI 2025 [4]：

- 俄罗斯已经审查发往 Cloudflare IP 的 ECH 连接
- 中国和伊朗通过审查加密 DNS 间接阻止 ECH
- 约 1/3 的 Cloudflare 服务器不支持 ECH

### 9.3 CDN 作为单点故障

如果审查方决定封锁所有 Cloudflare IP（中国已有先例局部封锁）：

- Mirage 所有用户立即失联
- 无回退机制（没有 domain fronting、没有 P2P、没有 bridge 分发）
- 对比：Snowflake 使用 ~100,000 个临时 WebRTC 代理 [5]，抗封锁弹性远超单一 CDN 依赖

---

## 10. 与同类工具的比较分析

### 10.1 技术路线对比

| 特性 | Mirage | NaiveProxy | VLESS+REALITY | Snowflake | UPGen |
|------|--------|------------|---------------|-----------|-------|
| TLS 指纹 | uTLS 库级模拟 | Chromium 原生网络栈 | 真实 TLS 握手 | WebRTC/DTLS | 生成式协议 |
| TLS-in-TLS 抗性 | ❌ 无 | ❌ 无 | ❌ 无 | ⚠️ 部分（WebRTC 噪声） | ✅ 无 TLS 封装 |
| 跨层 RTT 抗性 | ❌ 无 | ❌ 无 | ❌ 无 | ⚠️ 部分（多跳混淆） | ✅ 直连 |
| 主动探测抗性 | ✅ 真实网站 | ✅ Chrome 行为 | ⚠️ Aparecium [6] | ✅ | ✅ |
| CDN 依赖 | Cloudflare | 可选 | 无 | 分布式 | 无 |
| 部署复杂度 | 中等 | 高（需编译 Chromium） | 低 | 高（需 broker） | 高（学术原型） |

### 10.2 关键差距分析

**vs NaiveProxy**：
NaiveProxy 使用完整的 Chromium 网络栈而非 uTLS 库。sing-box 官方明确警告 [3]：

> "uTLS is not recommended for censorship circumvention due to fundamental architectural limitations; use NaiveProxy instead."

uTLS 的根本问题：它模拟 TLS ClientHello 的字节序列，但无法模拟 Chrome 的完整 TCP/TLS 行为（重传策略、窗口调整、ALPS、ECH 协商等）。高级审查者可以通过非 ClientHello 特征区分 uTLS 和真实 Chrome。

**vs UPGen (USENIX Security 2025)**：
UPGen [7] 提出了一种根本不同的思路：不模仿任何已知协议，而是**自动生成看起来像"未知但合理"的加密协议**。审查者要封锁 UPGen 流量，必须同时封锁所有未识别的加密流量，这会造成不可接受的附带损害（误伤 100% 的合法未知协议流量）。

**vs Geneva**：
Geneva [8] 使用遗传算法进化出 packet manipulation 策略（分片、乱序、重复、修改），在不需要代理的情况下绕过审查。已在中国、印度、伊朗、哈萨克斯坦实战部署。关键发现：存在**服务端**规避策略，无需客户端参与。

### 10.3 俄罗斯 TSPU 的启示

俄罗斯的 TSPU 系统 [9] 对 VLESS+REALITY 的打击策略值得关注：

- 不是封锁协议本身，而是对"可疑外国 IP 的 HTTPS 连接"进行**流量管制**
- 当 server→client 数据量 > 15-20KB 时，连接被"冻结"
- 这种基于**行为模式**的审查方法可以同样应用于 Mirage

---

## 11. 改良建议与路线图

### 11.1 架构层面（优先级：紧急）

#### A. 解决 TLS-in-TLS 指纹

**方案 1：真正的流多路复用 + 随机 padding 注入**

USENIX Security 2024 论文指出流多路复用是"有希望的反制手段但现有实现不足"。关键是要让多路复用**不仅共享连接，还要主动破坏内层握手的时序和大小特征**：

```
改良策略:
1. 在 Mux 层注入随机虚假流（发送 SYN + 随机数据 + FIN，模拟握手）
2. 对所有帧进行大小归一化（pad 到固定大小集合，如 {128, 512, 1500, 16384}）
3. 引入随机延迟缓冲：聚合多个流的帧后统一发送（交织流数据）
4. 使 Mux 帧大小与内层 TLS 握手大小解耦
```

**方案 2：协议层面消除 TLS 握手**

在 Mux 层预建多个"热备"流，当新连接到来时直接使用已有流传输数据，避免在可观察的时间窗口内产生新的 TLS 握手模式：

```
连接预热池:
- 维护 N 个预建立的 Mux 流
- 新 SOCKS5 连接 → 从池中取一个已建好的流
- 后台持续补充池中的流
- 流建立时机与用户行为解耦
```

#### B. 缓解跨层 RTT 指纹

**方案：请求管道化 + 批量化**

```
当前: 每个用户请求 → 立即通过 Mux 发送 → RTT 差异暴露
改良: 请求积累 → 批量发送 → 固定间隔（如 50ms）flush → RTT 被量化为固定步长
```

配合随机 padding 请求（不对应真实用户请求的虚假 request-response 对），使 RTT 分析变得不可靠。

#### C. 移除内层 QUIC 残留

清理 `internal/session/` 包和 `quic-go` 依赖，减少攻击面和二进制大小。

### 11.2 流量形态层面（优先级：高）

#### D. 集成 Morph 模块

**立即行动**：将 `internal/morph/` 集成到 `internal/carrier/client.go` 的 `upstreamLoop()` 和 `downstreamLoop()` 中：

```go
// 改良的 upstreamLoop 伪代码
func (c *ClientCarrier) upstreamLoop() {
    morpher := morph.New(10.0)
    streamStart := time.Now()
    for {
        data, _ := c.upstream.WaitAndDrain()
        age := time.Since(streamStart)

        // 注入 padding
        if morpher.ShouldPad(age) {
            padSize := morpher.PadSize()
            data = appendPadding(data, padSize)
        }

        // 应用延迟
        delay := morpher.InterPacketDelay(age)
        time.Sleep(delay)

        c.sendPost(data)
    }
}
```

#### E. 改进流量模拟

当前的帧大小分布是硬编码的且缺乏验证。建议：

1. **数据驱动**：收集真实 Cloudflare 视频流（YouTube 等）的 HTTP/2 帧大小分布，用其替换硬编码分布
2. **动态适应**：根据用户实际流量模式（浏览 vs 视频 vs 下载）选择不同的伪装模式
3. **双向 padding**：上行也需要 padding（当前仅下行有 keepalive）

#### F. 改进 Keepalive

```go
// 改良: 变间隔 keepalive
interval := 2*time.Second + time.Duration(rand.ExpFloat64()*3)*time.Second
// 产生 2-15s 的指数分布间隔，比固定 5s 更像真实视频缓冲
```

### 11.3 密码学层面（优先级：中）

#### G. 使用 KDF 替代裸 SHA256

```go
// 改良: 使用 Argon2id
import "golang.org/x/crypto/argon2"

func New(psk string) *Auth {
    salt := sha256.Sum256([]byte("MIRAGE-SALT-V1"))
    key := argon2.IDKey([]byte(psk), salt[:16], 1, 64*1024, 4, 32)
    ...
}
```

#### H. 添加 Nonce Map 容量上限

```go
const maxSeenNonces = 100_000

func (a *Auth) Validate(token string) (...) {
    // ... 验证成功后 ...
    a.mu.Lock()
    if len(a.seen) >= maxSeenNonces {
        return 0, nil, errors.New("rate limit exceeded")
    }
    a.seen[nonce] = time.Now().Add(a.maxAge * 2)
    a.mu.Unlock()
}
```

### 11.4 工程质量层面（优先级：中）

#### I. 优雅退出

```go
// 在 main.go 中添加
ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
defer stop()
srv.Shutdown(ctx) // 等待活跃连接完成
```

#### J. Mux 流控

实现基于信用的流控（类似 HTTP/2 WINDOW_UPDATE）：

```
新命令:
- CmdWND (4): 窗口更新帧，携带可接收的字节数
- 初始窗口: 1MB
- 发送方在窗口耗尽时阻塞而非丢包
```

#### K. Session 超时清理

```go
// 添加 session 最后活跃时间追踪
type serverSession struct {
    lastActive atomic.Int64  // Unix timestamp
    // ...
}

// 定期清理不活跃的 session
go func() {
    for range time.Tick(5 * time.Minute) {
        s.mu.Lock()
        for k, ss := range s.sessions {
            if time.Since(time.Unix(ss.lastActive.Load(), 0)) > 10*time.Minute {
                ss.sess.Close()
                delete(s.sessions, k)
            }
        }
        s.mu.Unlock()
    }
}()
```

#### L. 日志安全

```go
// 替换目标地址日志
if debugMode {
    log.Printf("proxy: %s", target)
} else {
    log.Printf("proxy: new connection (stream %d)", st.ID())
}
```

### 11.5 战略层面（优先级：长期）

#### M. 多 CDN 支持

不仅依赖 Cloudflare，还应支持 Fastly、Akamai 等 CDN 作为备用通道。当一个 CDN 被封锁时自动切换。

#### N. 考虑 UPGen 式的协议生成

长远来看，"模仿已知协议"的路线已被学术界证明存在根本缺陷。考虑集成 UPGen [7] 风格的协议生成，使每个部署实例使用不同的有线格式。

#### O. 考虑 WATER 框架集成

WATER [10]（WebAssembly Transport Executables Runtime）允许以 WebAssembly 模块形式动态分发新的传输协议，无需更新整个客户端。这使得：
- 新的规避策略可以在小时级别分发
- 每个用户可以运行不同的传输模块
- 审查者需要同时对抗数百种不同的有线格式

---

## 12. 参考文献

[1] Xue, D., Kallitsis, M., Houmansadr, A., & Ensafi, R. "Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes." *USENIX Security Symposium*, 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting

[2] Xue, D., Stanley, R., Kumar, P., & Ensafi, R. "The Discriminative Power of Cross-layer RTTs in Fingerprinting Proxy Traffic." *NDSS Symposium*, 2025. https://www.ndss-symposium.org/ndss-paper/the-discriminative-power-of-cross-layer-rtts-in-fingerprinting-proxy-traffic/

[3] sing-box Documentation. "uTLS is not recommended for censorship circumvention." https://sing-box.sagernet.org/

[4] Niere, N. et al. "Encrypted Client Hello (ECH) in Censorship Circumvention." *FOCI Workshop*, 2025. https://petsymposium.org/foci/2025/foci-2025-0016.php

[5] Bocovich, C. et al. "Snowflake, a censorship circumvention system using temporary WebRTC proxies." *USENIX Security Symposium*, 2024. https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich

[6] Aparecium: Detecting ShadowTLS v3 and REALITY. https://github.com/ban6cat6/aparecium

[7] Wails, R., Jansen, R., Johnson, A., & Sherr, M. "Censorship Evasion with Unidentified Protocol Generation (UPGen)." *USENIX Security Symposium*, 2025. https://www.usenix.org/conference/usenixsecurity25/presentation/wails

[8] Geneva: Genetic Evasion. University of Maryland. https://geneva.cs.umd.edu/

[9] net4people BBS. "Russia TSPU blocking VLESS+REALITY." https://github.com/net4people/bbs/issues/546

[10] WATER: WebAssembly Transport Executables Runtime. https://github.com/refraction-networking/water-rs

[11] Wu, M. et al. "How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic." *USENIX Security Symposium*, 2023. https://gfw.report/publications/usenixsecurity23/en/

[12] Wu, M. et al. "A Wall Behind A Wall: Emerging Regional Censorship in China." *IEEE Symposium on Security and Privacy*, 2025. https://gfw.report/publications/sp25/en/

[13] "Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China." *USENIX Security Symposium*, 2025. https://gfw.report/publications/usenixsecurity25/en/

[14] Xue, D. et al. "How China Detects and Blocks Shadowsocks." *ACM IMC*, 2020. https://dl.acm.org/doi/10.1145/3419394.3423644

[15] Subramani, K., Perdisci, R. et al. "Discovering and Measuring CDNs Prone to Domain Fronting." *ACM Web Conference*, 2024. https://dl.acm.org/doi/10.1145/3589334.3645656

[16] JA4+ Network Fingerprinting Suite. FoxIO. https://github.com/FoxIO-LLC/ja4

[17] NaiveProxy. https://github.com/klzgrad/naiveproxy

[18] CensorLess: Censorship Circumvention Through Serverless Cloud Functions. 2026. https://arxiv.org/abs/2603.00345

[19] Mueller, P. et al. "Turning Attacks into Advantages: Evading HTTP Censorship with HTTP Request Smuggling." *FOCI Workshop*, 2024. https://www.petsymposium.org/foci/2024/foci-2024-0012.php

[20] "GFW Unconditional Port 443 Block." GFW Report, August 2025. https://gfw.report/blog/gfw_unconditional_rst_20250820/en/

---

> **免责声明**：本文档仅用于技术研究和教育目的。流量混淆和审查规避技术的使用应遵守所在司法管辖区的法律法规。
