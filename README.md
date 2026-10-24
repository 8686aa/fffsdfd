# StarRadar iOS（局域网 SOCKS5 版）

把手机变成一台**局域网 SOCKS5 代理**，让同一 Wi-Fi 下的另一台设备
（另一部手机 / 平板 / 电脑）扫码接入。代理侧只对**对局端口**做 TGCP 帧翻译、
抓取对局参数并上报，其余端口直连转发，UDP 经过滤后上报。

协议层与 PC 端（Python）、Android 端（Kotlin）**逐字节一致**，三方共用
同一批由 Python 生成的交叉验证向量。

```
另一台设备（sing-box / Shadowrocket / NekoBox）
        │  SOCKS5 192.168.x.x:1083
        ▼
   ┌─────────────────────────────┐
   │ Socks5Server（本机监听）      │
   │  ├ 65010   → SocketTunnel    │──▶ TgcpEngine ──▶ 真游戏服务器
   │  │            └ 母料 ──▶ Uploader（battle_key）
   │  ├ 其它端口 → 直连转发         │
   │  └ UDP ASSOCIATE             │──▶ UdpGate ──▶ 上报
   └─────────────────────────────┘
        │  HTTP :8088
        └─ /share/{singbox,shadowrocket,nekobox}（供 sing-box 拉 profile）
```

---

## 目录

```
starradar-ios/
├── Core/                    SwiftPM 包：协议与纯逻辑（可在 macOS 上 swift test）
│   ├── Sources/StarRadarCore/
│   │   ├── Tgcp.swift           帧结构 / DH / native 填充 / body 翻译
│   │   ├── TgcpConstants.swift  由 tools/gen_swift_constants.py 从 PC 源码生成
│   │   ├── BigUInt.swift        自写大数 + Montgomery 模幂（不引第三方包）
│   │   ├── AES.swift            AES-CBC（运行时生成 S-box）
│   │   ├── Crypto.swift         SHA256/HMAC/HKDF/AES-GCM（CryptoKit）
│   │   ├── SecureWs.swift       上报通道加密（HKDF + 信封）
│   │   ├── WsClient.swift       URLSessionWebSocketTask 封装
│   │   ├── Uploader.swift       鉴权 / 密钥下发 / 批量上报
│   │   ├── Socks5Proto.swift    RFC1928/1929 编解码
│   │   ├── IpDatagram.swift     IPv4+UDP 报文重建（含校验和）
│   │   ├── ShareLinks.swift     三种客户端的链接 / 订阅 / 配置
│   │   ├── ShareSite.swift      内置网页地址解析（归一化成 节点IP:666）
│   │   ├── NodeProbe.swift      6 步节点自检
│   │   ├── UdpGate.swift        上报过滤（时长 + 包数 + 双向）
│   │   └── UdpReport.swift      UDP 方向规范化
│   └── Tests/StarRadarCoreTests/ 向量测试（共用 PC 生成的 JSON）
├── App/                     SwiftUI 界面 + 网络监听
│   ├── Info.plist
│   └── Sources/StarRadar/
│       ├── Net/                 NetSocket / Socks5Server / UdpRelay /
│       │                        TgcpEngine / SocketTunnel / ShareHttpServer /
│       │                        LanAddress / EgressCheck
│       ├── Service/             RadarService / KeepAlive / Settings
│       └── UI/                  Theme / HomeView / QrView / BuiltinWebView
├── scripts/build_ipa.sh     本地 macOS 出包
└── tools/gen_swift_constants.py
```

根目录 `.github/workflows/ios-ipa.yml`：在 macOS runner 上跑向量测试 +
无签名构建 + 上传 ipa。

---

## 构建

### GitHub Actions（推荐，本机不需要 Mac）

推送到 `main`/`master` 或手动 `workflow_dispatch` 即会：

1. `Core` 跑向量测试（与 PC/Android 对同一批向量）
2. `xcodegen generate`
3. `xcodebuild ... CODE_SIGNING_ALLOWED=NO`
4. 打包 `Payload/StarRadar.app` → `StarRadar-unsigned.ipa`
5. 作为 artifact 上传

### 本地（macOS）

```bash
./scripts/build_ipa.sh
# 产物：starradar-ios/StarRadar-unsigned.ipa
```

### 安装

无签名 ipa **不能直接双击安装**。用侧载工具（AltStore / Sideloadly /
TrollStore 等）安装；企业签名/自签证书的流程不在本仓库范围内。

---

## iOS 与 Android 的差异（必须知道）

| 项 | Android 版 | iOS 版 |
|---|---|---|
| 入口 | VpnService 接管本机 / SOCKS5 服务端 | **只有** SOCKS5 服务端 |
| 全局代理 | 可以 | 不行（无 NetworkExtension 授权时无法建 TUN） |
| 后台常驻 | WakeLock + WifiLock | **只能靠静音音频**（`UIBackgroundModes: audio`），设置里可关 |
| 防锁屏 | 无 | `isIdleTimerDisabled`（这条收益最大） |
| 局域网授权 | 无 | iOS 14+ 首次会弹「本地网络」授权，必须允许 |

静音音频不是正规用途（上架会被拒），本项目按侧载分发。关掉它更省电，
但切后台约 30 秒后 socket 会被系统挂起 —— 另一台设备会断。

---

## 使用流程

1. 本机连上 Wi-Fi（或开热点让另一台设备连过来）
2. 填节点 IP 与 32 位房间口令 → 保存
3. 点「开始代理」
4. 先点「节点自检」，六步全绿说明节点可达、口令有效、会话密钥一致
5. 点「生成二维码」，另一台设备按装的客户端扫对应那张
   - **sing-box**：`import-remote-profile` deep link，需要本机 HTTP 服务在跑
   - **Shadowrocket / NekoBox**：明文 `socks5://`（不带 `#备注`，否则会多出一个分组）
6. 另一台设备开 TUN 模式 → 进游戏
7. 界面出现「对局参数」计数即抓到母料；「打开内置网页」此时才可用

---

## 端口与约定

| 用途 | 端口 |
|---|---|
| SOCKS5 监听 | 1083（可改） |
| 配置服务（sing-box 拉 profile） | 8088（可改，占用则顺延） |
| 上报 WebSocket | 1082（固定，节点侧） |
| 内置网页接口 | 666（固定，节点侧） |
| 对局端口（走帧翻译） | 65010 |

---

## 验证情况

已在本仓库内可复现：

- **协议向量**：`minimal_be` / `dh`（含 512 位模幂）/ `pad_len` / `strip` /
  `translate` / `pack` / `framer` / `framer_partial` / `replace_dh` /
  `secure_ws`（HKDF、roomId、transcript）/ `envelope`（GCM 逐字节）/ `batch`
- **扫码链接**：percent 编码 / 三种客户端链接 / 订阅 / `.conf` / UDP 封装
- **AES**：FIPS-197 已知答案 + S-box 定点值
- **UDP 过滤**：系统端口、媒体端口、双向判据、大流量放行、单向判死

**未在本机验证**（Windows 上没有 Xcode，也没有真机）：

- 实际编译通过性（由 CI 的 macOS runner 保证）
- 真机上的局域网授权、SOCKS5 连通性、游戏内实际抓取
- 后台静音音频是否被系统持续允许（依赖机型与省电策略）

第一次真机跑建议按这个顺序看：节点自检 → 另一台设备连接 → 界面「连接/活跃」
是否上涨 → 「对局参数」是否出现。
