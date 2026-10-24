import Foundation
import AVFoundation
import MediaPlayer
import UIKit
import StarRadarCore

/**
 后台保活。

 ## iOS 的限制必须先说清楚

 Android 端拿 WakeLock + WifiLock 就能常驻；iOS **没有**这种能力：App 进后台
 约 30 秒后会被系统挂起，socket 随之停摆。所以「切后台不断网」在 iOS 上只有
 一条路：**音频后台模式**（`UIBackgroundModes: audio`）—— 播放一路静音音频，
 让进程一直处于「正在后台播放音频」状态，系统就不会挂起它。

 这不是正规用途（App Store 会拒），但本项目是侧载分发（无签名 ipa），可用。

 ## 原来的版本为什么「开了也没用」

 只做了一件事：`AVAudioPlayer.play()` 一次。四个原因会让它形同虚设：

 ① **`volume = 0`**。iOS 会据此把这路音频当成「没有实际输出」，后台音频
    的优先级随之被降掉，于是照样被挂起。静音要靠**采样值**（全零），而不是
    把音量拧到 0。
 ② **`.mixWithOthers`**。这是「和别的 App 混音」的次要会话，系统对它的后台
    驻留意愿明显更低。很多机型上必须独占会话才稳。
 ③ **打断后不恢复**。来电 / 闹钟 / 视频通话 / 拔耳机 / 蓝牙断开 /
    媒体服务重启，任何一种都会停掉这路音频 —— 而原来的代码只在「开始代理」
    时调用过一次 `play()`，之后再也不会重来。于是音频一停，30 秒后必然被挂起。
 ④ **没有自愈**。播放器异常停止时 `isPlaying` 变 false，没有任何人管。

 ## 现在的做法

 - **看门狗**（5 秒一跳）：发现 `isPlaying == false` 就重建。
 - **自适应升级**：先试混音会话；若在混音模式下反复掉线，自动升级到独占会话
   （宁可暂停用户的音乐，也要保证代理不断）。
 - **打断/路由/媒体服务通知**：收到就重建；打断结束（`.shouldResume`）主动恢复。
  打断期间不盲目重建 —— 那时音频会话被别人占着，重建只会一直失败。
 - **回到前台**立刻跑一次心跳。
 - **挂起检测**：看门狗在后台每 5 秒一跳；某一跳间隔超过 `suspendThreshold`
  说明 App **真的被挂起过**。这时回调 `onSuspended`，让上层把已经没人读的
  旧连接清掉，否则客户端会对着一条静默连接干等几分钟才重连。
 */
final class KeepAlive {

    /// 看门狗间隔。5 秒足够快，又不会明显耗电。
    static let watchdogInterval: TimeInterval = 5
    /// 两跳间隔超过这个秒数 → 判定「期间被系统挂起过」。
    static let suspendThreshold: TimeInterval = 12
    /// 混音模式下丢掉几次之后升级到独占会话。
    static let escalationThreshold = 2

    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private var renewTimer: Timer?
    private var watchdog: Timer?
    private var player: AVAudioPlayer?
    private let audioEnabled: Bool
    private var observers: [NSObjectProtocol] = []

    private(set) var audioRunning = false
    private(set) var summary = ""

    /// 混音模式下掉线次数；到阈值就升级独占。
    private var audioLosses = 0
    /// 是否已升级到独占会话。
    private(set) var strictAudio = false
    /// 当前是否处于系统打断中（来电等）。打断期间不做重建尝试。
    private var interrupted = false

    /// 最近一次心跳。回到前台时用它计算「被挂起了多久」。
    private(set) var lastBeat = Date()
    /// 本次后台已持续秒数（在前台时为 0）。
    private(set) var backgroundSeconds = 0
    /// 音频重建次数。界面显示它就能看出「保活是不是一直在跟系统打架」。
    private(set) var rebuildCount = 0

    /// 检测到「App 曾被系统挂起」时回调，参数是估算的挂起秒数。
    var onSuspended: ((Int) -> Void)?
    /// 保活自己的日志，上层并进主日志流。
    var onLog: ((String) -> Void)?

    init(audioEnabled: Bool) {
        self.audioEnabled = audioEnabled
    }

    // ── 启停 ──────────────────────────────────────────────────

    @discardableResult
    func acquire() -> String {
        UIApplication.shared.isIdleTimerDisabled = true
        installObservers()
        beginBackgroundTask()
        startWatchdog()
        if audioEnabled {
            installNowPlaying()
            audioRunning = rebuildAudio(reason: "启动")
        }
        lastBeat = Date()
        updateSummary()
        return summary
    }

    func release() {
        UIApplication.shared.isIdleTimerDisabled = false
        renewTimer?.invalidate()
        renewTimer = nil
        watchdog?.invalidate()
        watchdog = nil
        endBackgroundTask()
        stopAudio()
        removeNowPlaying()
        removeObservers()
        audioRunning = false
        backgroundSeconds = 0
        summary = ""
        onSuspended = nil
        onLog = nil
        try? AVAudioSession.sharedInstance().setActive(
            false, options: .notifyOthersOnDeactivation)
    }

    // ── 静音音频 ──────────────────────────────────────────────

    /// 重建音频通道。任何「音频可能已经死了」的迹象都走这里。
    @discardableResult
    private func rebuildAudio(reason: String) -> Bool {
        stopAudio()
        // 先试混音（不打断用户的音乐）。反复掉线说明混音会话不被系统当回事，
        // 升级到独占 —— 代理不断比「别停我的歌」重要。
        if !strictAudio {
            if startAudio(options: [.mixWithOthers], label: "混音") { return true }
            strictAudio = true
            log("[ka] 混音会话起不来，升级为独占会话")
        }
        if startAudio(options: [], label: "独占") { return true }
        log("[ka] 静音音频启动失败（\(reason)）")
        return false
    }

    private func startAudio(options: AVAudioSession.CategoryOptions,
                            label: String) -> Bool {
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default, options: options)
            try session.setActive(true)
            let player = try AVAudioPlayer(data: KeepAlive.silentWav())
            player.numberOfLoops = -1          // 无限循环
            // 静音靠采样值（全零），**不能**把 volume 设成 0：
            // 那会让系统认为这路音频没有输出，后台优先级被降掉。
            player.volume = 1.0
            player.prepareToPlay()
            guard player.play() else { return false }
            self.player = player
            rebuildCount += 1
            log("[ka] 静音音频已就绪（\(label)会话 · 第 \(rebuildCount) 次）")
            return true
        } catch {
            return false
        }
    }

    private func stopAudio() {
        player?.stop()
        player = nil
    }

    // ── 看门狗 ────────────────────────────────────────────────

    private func startWatchdog() {
        watchdog?.invalidate()
        let timer = Timer.scheduledTimer(withTimeInterval: KeepAlive.watchdogInterval,
                                         repeats: true) { [weak self] _ in
            self?.beat()
        }
        // .common 模式：滚动界面时也要跳，否则拖动一下就当成了「被挂起」
        RunLoop.main.add(timer, forMode: .common)
        watchdog = timer
    }

    private func beat() {
        let now = Date()
        let gap = now.timeIntervalSince(lastBeat)
        lastBeat = now

        // ① 先判断有没有被挂起过。Timer 在挂起期间不会跳，所以「间隔异常大」
        //    是挂起的唯一可靠信号。必须放在最前面。
        if gap > KeepAlive.suspendThreshold {
            let seconds = Int(gap)
            log("[ka] 检测到系统曾挂起 App 约 \(seconds) 秒")
            interrupted = false
            if audioEnabled { audioRunning = rebuildAudio(reason: "挂起恢复") }
            onSuspended?(seconds)
        }

        // ② 常规自愈。打断期间跳过 —— 那时会话被别的 App 占着，
        //    重建只会一路失败，还会把「掉线次数」算进去误升级。
        if audioEnabled && !interrupted {
            if !audioRunning {
                audioRunning = rebuildAudio(reason: "看门狗发现未运行")
            } else if let player, !player.isPlaying {
                audioLosses += 1
                log("[ka] 播放器已停止（混音模式掉线 \(audioLosses) 次）")
                if audioLosses >= KeepAlive.escalationThreshold && !strictAudio {
                    strictAudio = true
                    log("[ka] 反复掉线，升级为独占音频会话")
                }
                audioRunning = rebuildAudio(reason: "播放器已停止")
            }
        }

        if UIApplication.shared.applicationState == .background {
            backgroundSeconds += Int(KeepAlive.watchdogInterval)
        } else {
            backgroundSeconds = 0
        }
        updateSummary()
    }

    private func updateSummary() {
        if interrupted {
            summary = "后台保活暂挂：音频被系统打断（通话 / 其它 App 占用），"
                + "结束后会自动恢复。打断时间过长系统仍会挂起本 App"
            return
        }
        if audioRunning {
            let mode = strictAudio ? "独占音频" : "混音音频"
            summary = "后台保活已启用（\(mode) + 防锁屏）"
            if rebuildCount > 1 {
                summary += " · 已自愈 \(rebuildCount - 1) 次"
            }
        } else if audioEnabled {
            summary = "后台保活失败：静音音频起不来。切后台约 30 秒后会被系统挂起，"
                + "另一台设备会断网。请关掉低电量模式后重新开始代理"
        } else {
            summary = "静音音频已关闭：切后台约 30 秒后会被系统挂起，另一台设备断网"
        }
    }

    // ── 通知 ──────────────────────────────────────────────────

    private func installObservers() {
        removeObservers()
        let center = NotificationCenter.default

        observers.append(center.addObserver(
            forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            guard let self else { return }
            self.backgroundSeconds = 0
            self.lastBeat = Date()
            // 进后台的那一刻最关键：音频必须已经在响。
            if self.audioEnabled && !self.audioRunning && !self.interrupted {
                self.audioRunning = self.rebuildAudio(reason: "进入后台")
            }
            self.beginBackgroundTask()
        })

        observers.append(center.addObserver(
            forName: UIApplication.willEnterForegroundNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            // 立刻心跳一次：顺带判断「刚才是不是被挂起过」，不用等下一个 5 秒。
            self?.beat()
        })

        observers.append(center.addObserver(
            forName: AVAudioSession.interruptionNotification,
            object: nil, queue: .main
        ) { [weak self] note in
            self?.handleInterruption(note)
        })

        observers.append(center.addObserver(
            forName: AVAudioSession.routeChangeNotification,
            object: nil, queue: .main
        ) { [weak self] note in
            guard let self, self.audioEnabled, !self.interrupted else { return }
            guard let raw = note.userInfo?[AVAudioSessionRouteChangeReasonKey]
                    as? UInt,
                  let reason = AVAudioSession.RouteChangeReason(rawValue: raw)
            else { return }
            // 耳机拔掉 / 蓝牙断开：系统会停掉当前路由上的播放
            if reason == .oldDeviceUnavailable || reason == .routeConfigurationChange {
                log("[ka] 音频路由变化（\(reason.rawValue)），重建音频")
                self.audioRunning = self.rebuildAudio(reason: "音频路由变化")
            }
        })

        observers.append(center.addObserver(
            forName: AVAudioSession.mediaServicesWereResetNotification,
            object: nil, queue: .main
        ) { [weak self] _ in
            // 媒体服务被系统重启过，旧播放器全部失效
            guard let self, self.audioEnabled else { return }
            self.interrupted = false
            self.audioRunning = self.rebuildAudio(reason: "媒体服务重启")
        })
    }

    private func handleInterruption(_ note: Notification) {
        guard let raw = note.userInfo?[AVAudioSessionInterruptionTypeKey] as? UInt,
              let type = AVAudioSession.InterruptionType(rawValue: raw) else { return }
        switch type {
        case .began:
            // 被来电 / 别的 App 抢走了音频。这时重建没有意义，只标记状态，
            // 等 .ended 再恢复。
            interrupted = true
            audioRunning = false
            log("[ka] 音频被系统打断（来电或其它 App 抢占），等结束后自动恢复")
        case .ended:
            interrupted = false
            guard audioEnabled else { return }
            let options = (note.userInfo?[AVAudioSessionInterruptionOptionKey]
                           as? UInt).map {
                AVAudioSession.InterruptionOptions(rawValue: $0)
            }
            if options?.contains(.shouldResume) ?? true {
                audioRunning = rebuildAudio(reason: "打断结束")
            }
        @unknown default:
            break
        }
    }

    private func removeObservers() {
        let center = NotificationCenter.default
        for token in observers { center.removeObserver(token) }
        observers.removeAll()
    }

    // ── 媒体会话身份 ──────────────────────────────────────────

    /**
     把本 App 登记为系统的「正在播放」媒体 App。

     ## 为什么这条很重要

     `UIBackgroundModes: audio` 只给了「可以后台播音频」的**资格**，系统是否
     真的让进程常驻，还看它认不认为你是一个「正在播放的媒体 App」。只调用
     `AVAudioPlayer.play()` 而不登记 now-playing 时，很多机型会把本 App 当成
     「随便放了个静音文件」并按普通 App 的规则挂起 —— 这正是「开了静音音频
     仍然被挂起」的常见原因。

     `MPNowPlayingInfoCenter` + `beginReceivingRemoteControlEvents()` 一起用，
     系统才会把本 App 归到「正在播放」那一类，后台存活优先级随之提高。
     锁屏上会出现一张「正在保持代理连接」的卡片 —— 这既是代价也是收益：
     用户能直接看到代理还在跑。
     */
    private func installNowPlaying() {
        let commands = MPRemoteCommandCenter.shared()
        // 这是无声的维持流，给播放/暂停按钮没有意义，按了就乱
        commands.playCommand.isEnabled = false
        commands.pauseCommand.isEnabled = false
        commands.togglePlayPauseCommand.isEnabled = false
        commands.nextTrackCommand.isEnabled = false
        commands.previousTrackCommand.isEnabled = false

        MPNowPlayingInfoCenter.default().nowPlayingInfo = [
            MPMediaItemPropertyTitle: "代理运行中",
            MPMediaItemPropertyArtist: "APP",
            MPNowPlayingInfoPropertyIsLiveStream: true,
            MPNowPlayingInfoPropertyPlaybackRate: 1.0,
        ]
        UIApplication.shared.beginReceivingRemoteControlEvents()
    }

    private func removeNowPlaying() {
        MPNowPlayingInfoCenter.default().nowPlayingInfo = nil
        UIApplication.shared.endReceivingRemoteControlEvents()
    }

    // ── 短时后台任务 ──────────────────────────────────────────

    private func beginBackgroundTask() {
        endBackgroundTask()
        backgroundTask = UIApplication.shared.beginBackgroundTask(
            withName: "StarRadarProxy"
        ) { [weak self] in
            self?.endBackgroundTask()
        }
        if renewTimer == nil {
            // 这一路只给「切出去马上回来」兜底（约 30 秒）；常驻靠音频。
            renewTimer = Timer.scheduledTimer(withTimeInterval: 25, repeats: true) {
                [weak self] _ in
                guard let self else { return }
                if UIApplication.shared.applicationState == .background {
                    self.beginBackgroundTask()
                }
            }
        }
    }

    private func endBackgroundTask() {
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    // ── 日志 ──────────────────────────────────────────────────

    private func log(_ text: String) {
        onLog?(text)
    }

    // ── 静音 WAV ──────────────────────────────────────────────

    /// 生成 1 秒静音 WAV（**16 位** PCM，全零采样）。
    ///
    /// 刻意不用 8 位：部分系统版本上 `AVAudioPlayer` 对 8 位 WAV 的解码路径
    /// 不稳，会出现 `play()` 返回 true 但 `isPlaying` 立刻变 false。
    /// 也不用外置音频文件 —— 无签名 ipa 打包时资源目录最容易出问题。
    static func silentWav(seconds: Int = 1, sampleRate: Int = 44100) -> Data {
        let frames = sampleRate * seconds
        let dataBytes = frames * 2                  // 16 位单声道
        var data = Data(capacity: 44 + dataBytes)

        func le32(_ value: Int) {
            var little = UInt32(value).littleEndian
            withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
        }
        func le16(_ value: Int) {
            var little = UInt16(value).littleEndian
            withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
        }

        data.append(contentsOf: Array("RIFF".utf8))
        le32(36 + dataBytes)
        data.append(contentsOf: Array("WAVE".utf8))
        data.append(contentsOf: Array("fmt ".utf8))
        le32(16)                                    // fmt chunk 长度
        le16(1)                                     // PCM
        le16(1)                                     // 单声道
        le32(sampleRate)
        le32(sampleRate * 2)                        // byteRate = rate * 1ch * 2B
        le16(2)                                     // blockAlign
        le16(16)                                    // bits per sample
        data.append(contentsOf: Array("data".utf8))
        le32(dataBytes)
        data.append(Data(repeating: 0, count: dataBytes))   // 16 位静音 = 全 0
        return data
    }
}
