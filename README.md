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

### 已经在 CI 上跑通的（就是证据，不是预计）

Run #40086825246：

```
Core vector tests   success      ← 与 PC/Android 共用同一批向量
unsigned ipa        success
  show Xcode versions / select Xcode / install xcodegen / generate project
  build (no signing) / package ipa / upload artifact   ← 全部 ok
```

产物 `StarRadar-unsigned.ipa`（434 KB artifact，解包后 448 KB）：

| 检查 | 结果 |
|---|---|
| 结构 | `Payload/StarRadar.app/`，无多余层级 |
| 显示名 | `APP` |
| bundle id | `com.starradar.ios`（`$(...)` 已展开） |
| 版本 | 1.0.0 (1) |
| 后台模式 | `audio` |
| 局域网授权描述 | 有 |
| ATS | `NSAllowsArbitraryLoads = true` |
| 可执行文件 | 1.53 MB，arm64 单架构，`MH_MAGIC_64` |
| 平台 / 最低系统 | iOS / 15.0（SDK 26.2） |
| 签名 | **无** `_CodeSignature`、无 `embedded.mobileprovision` |

本地复验：

```bash
python3 tools/verify_ipa.py artifacts/StarRadar-unsigned.ipa
# 22 项通过，0 项失败
```

### 还没验证的（必须真机）

- 首次启动的「本地网络」授权弹窗
- 另一台设备经 SOCKS5 实际联网、进游戏
- 静音音频在息屏后是否被系统杀掉（依机型与省电策略）
- 对局端口 65010 的帧翻译在真实会话里是否稳定

---

## 踩过的坑（都写在代码注释里了）

出 ipa 这条链路一共失败 6 次，每次都是具体问题，记下来省得重踩：

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | `AES.GCM` 找不到 | 本模块自己定义了 `AES`（AES-CBC），与 `CryptoKit.AES` 撞名 | 全限定 `CryptoKit.AES.GCM` |
| 2 | `>=` 不可用 | `BigUInt` 只写了 `<` `>` `==`，没遵循 `Comparable` | 声明 `: Comparable` |
| 3 | switch 不穷尽 | `switch State?` 时穷尽性按 `State` 全部 case 算 | 补 `case .hold, nil` |
| 4 | 测试崩 `unexpectedly found nil` | `envelope.firstPlaintext_utf8` 与 `first` **同级**，被当成子键 | 改取值路径 |
| 5 | `Unable to read project ... format (77)` | XcodeGen 出 objectVersion 77，macos-14 是 Xcode 15.4（只到 60） | ipa job 换 `macos-15` |
| 6 | `overlapping accesses to 'buffer'` | `withUnsafeMutableBytes` 闭包里读了 `buffer.count` | 容量在闭包外取好 |

另外两个不是「编译错误」但更值得记的：

- **`BigUInt.multiply` 的最终归约丢了 `t[size]`**。CIOS 结束时真实值是
  `t[size]·2^(32·size) + 低 size 位`，可能落在 `[n, 2n)`。漏掉这行**不会在
  P（512 位素数）上必现** —— 某些中间值恰好让 `t[size]=0`，于是「大部分对、
  偶发算错」。我用 Python 逐行复现该算法才抓到：修正前 16~512 位随机奇数模数
  24 例错 9 例，修正后 16~1024 位 40 例全过。
- **`binaryModPow` 里用加法当乘方**（`addMod(r, r)` 算的是 `2r` 不是 `r²`）。
  它是「偶数模数」的兜底路径，而 P 是奇数所以从未触发 —— 这种「静默错路」
  比直接崩更危险，已删掉，改成 `precondition` 要求奇数模数。

---

## 关于 token

推送用 Personal Access Token 走 API（`scripts/push_via_api.py`）。
推送完成后应当**立刻撤销**这个 token：

```
https://github.com/settings/tokens → 找到对应条目 → Delete
```

---

## 后台运行（iOS 的硬限制与应对）

Android 能拿 WakeLock + WifiLock 常驻，iOS **没有**对等能力。App 进后台约
30 秒后会被系统挂起，socket 随之停摆 —— 表现就是「另一台设备连着但没网」。

唯一可行的手段是**音频后台模式**：`UIBackgroundModes: audio` + 一直播放
一路静音音频，让进程处于「正在后台播放」状态。侧载分发不受 App Store 审核
约束，所以这条路可用；设置里给了开关（关掉更省电，但切后台即断）。

### 光「播一次静音」是不够的

这路音频很容易被打断，而且打断后不会自己回来。`KeepAlive` 现在处理这些：

| 打断来源 | 处理 |
|---|---|
| 来电 / 闹钟 / 视频通话 | 监听 `interruptionNotification`，`.ended` 且 `.shouldResume` 就重建 |
| 拔耳机 / 蓝牙断开 | 监听 `routeChangeNotification`，`.oldDeviceUnavailable` 就重建 |
| 媒体服务被系统重启 | 监听 `mediaServicesWereResetNotification`，重建 |
| 播放器异常停止 | 5 秒一次的看门狗检查 `isPlaying`，停了就重建 |
| 混音会话不被系统重视 | 反复掉线 2 次后自动升级为**独占**音频会话 |

两个容易踩的点：

- **静音必须靠采样值（全零 16 位 PCM），不能 `volume = 0`**。音量设 0 会让
  系统认为这路音频「没有实际输出」，后台优先级被降掉，照样被挂起。
- **要登记 now-playing**（`MPNowPlayingInfoCenter` + `beginReceivingRemoteControlEvents`）。
  只 `play()` 而不登记时，很多机型把本 App 当普通 App 挂起。登记后锁屏上会
  出现一张「代理运行中」的卡片 —— 这既是代价也是收益，用户能直接看到在跑。

### 还是被挂起了怎么办

会检测出来并自救：看门狗在后台每 5 秒一跳，如果某一跳与上一跳间隔超过 12 秒，
说明 App 真的被挂起过。这时：

- 挂起 < 60 秒：连接保留（挂起期间内核仍在缓冲数据，恢复后能继续读）
- 挂起 ≥ 60 秒：主动断开旧连接，让客户端立刻重连（否则它会对着静默连接
  干等 TCP 重传超时，几分钟才恢复）

界面上会显示「曾检测到系统挂起 App 约 N 秒」，日志里是 `[ka]` 开头。

### 仍然无解的部分

- **从多任务界面划掉 App**：进程直接没了，任何保活都无效。
- **低电量模式**：系统会明显更积极回收后台 App，界面会给出黄色提示。
- **长时间后台（数小时）**：个别机型仍会回收。这是平台行为，不是代码问题。
