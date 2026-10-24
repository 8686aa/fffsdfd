import Foundation
import AVFoundation
import UIKit
import StarRadarCore

/**
 后台保活。

 ## iOS 的限制必须先说清楚

 Android 端拿 WakeLock + WifiLock 就能常驻；iOS **没有**这种能力：
 App 进后台约 30 秒后会被系统挂起，socket 也随之停摆。所以「切后台不断网」
 在 iOS 上只有靠 **音频后台模式**（`UIBackgroundModes: audio`）——
 播放一路静音音频，让进程保持运行。

 这不是正规用途（App Store 会拒），但本项目是侧载分发（无签名 ipa），
 所以是可用的。设置里给了开关：关掉更省电，但切后台就会断。

 ## 另外两件有用的事

 - `isIdleTimerDisabled = true`：不让屏幕自动锁。锁屏才是最容易被挂起的场景，
   这一条几乎不影响耗电，收益却最大。
 - `beginBackgroundTask` + 定时续期：给「切出去接个电话马上回来」这种
   短时离开兜底。
 */
final class KeepAlive {

    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private var renewTimer: Timer?
    private var player: AVAudioPlayer?
    private let audioEnabled: Bool

    private(set) var audioRunning = false
    private(set) var summary = ""

    init(audioEnabled: Bool) {
        self.audioEnabled = audioEnabled
    }

    @discardableResult
    func acquire() -> String {
        UIApplication.shared.isIdleTimerDisabled = true
        beginBackgroundTask()
        if audioEnabled {
            audioRunning = startSilentAudio()
        }
        if audioRunning {
            summary = "后台保活已启用（静音音频 + 防锁屏）"
        } else {
            summary = "后台保活部分启用（防锁屏 + 短时后台）；" +
                (audioEnabled ? "静音音频启动失败" : "静音音频已关闭")
        }
        return summary
    }

    func release() {
        UIApplication.shared.isIdleTimerDisabled = false
        renewTimer?.invalidate()
        renewTimer = nil
        endBackgroundTask()
        player?.stop()
        player = nil
        audioRunning = false
        summary = ""
        try? AVAudioSession.sharedInstance().setActive(false,
                                                      options: .notifyOthersOnDeactivation)
    }

    // ── 短时后台任务 + 续期 ───────────────────────────────────

    private func beginBackgroundTask() {
        endBackgroundTask()
        backgroundTask = UIApplication.shared.beginBackgroundTask(
            withName: "StarRadarProxy"
        ) { [weak self] in
            self?.endBackgroundTask()
        }
        if renewTimer == nil {
            // 每次续期都是一次新的后台任务；只在真的处于后台时才续，
            // 前台时续期没有意义还会白白消耗配额。
            renewTimer = Timer.scheduledTimer(withTimeInterval: 20, repeats: true) {
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

    // ── 静音音频 ──────────────────────────────────────────────

    private func startSilentAudio() -> Bool {
        do {
            let session = AVAudioSession.sharedInstance()
            try session.setCategory(.playback, mode: .default,
                                    options: [.mixWithOthers])
            try session.setActive(true)
            let player = try AVAudioPlayer(data: KeepAlive.silentWav())
            player.numberOfLoops = -1
            player.volume = 0
            player.prepareToPlay()
            guard player.play() else { return false }
            self.player = player
            return true
        } catch {
            return false
        }
    }

    /// 生成 1 秒静音 WAV（8-bit PCM，值 0x80 = 静音）。
    ///
    /// 刻意不往 bundle 里放音频文件：无签名 ipa 打包时资源目录最容易出
    /// 问题（漏拷、路径大小写），而这段数据完全可以在内存里拼出来。
    static func silentWav(seconds: Int = 1, sampleRate: Int = 8000) -> Data {
        let sampleCount = sampleRate * seconds
        var data = Data()
        func appendLE32(_ value: Int) {
            var little = UInt32(value).littleEndian
            withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
        }
        func appendLE16(_ value: Int) {
            var little = UInt16(value).littleEndian
            withUnsafeBytes(of: &little) { data.append(contentsOf: $0) }
        }

        data.append(contentsOf: Array("RIFF".utf8))
        appendLE32(36 + sampleCount)
        data.append(contentsOf: Array("WAVE".utf8))
        data.append(contentsOf: Array("fmt ".utf8))
        appendLE32(16)
        appendLE16(1)                       // PCM
        appendLE16(1)                       // 单声道
        appendLE32(sampleRate)
        appendLE32(sampleRate)              // byteRate = rate * 1 * 1
        appendLE16(1)                       // blockAlign
        appendLE16(8)                       // bits per sample
        data.append(contentsOf: Array("data".utf8))
        appendLE32(sampleCount)
        data.append(Data(repeating: 0x80, count: sampleCount))
        return data
    }
}
