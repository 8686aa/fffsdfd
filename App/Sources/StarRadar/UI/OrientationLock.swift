import UIKit

/**
 全局方向锁。

 ## 为什么需要它

 主页是竖屏布局（卡片纵向排列），横过来会很难看；而内置网页是「战术雷达」
 那种表格/地图页面，**横屏才有意义**。

 iOS 的两层限制必须同时处理，缺一不可：

 1. `Info.plist` 的 `UISupportedInterfaceOrientations` —— App 整体允许哪些方向
 2. `application(_:supportedInterfaceOrientationsFor:)` —— 当前这一刻允许哪些

 系统取两者**交集**。所以只在 delegate 里返回横屏是不够的：plist 里没写
  landscape，交集仍然是竖屏，转不过来（而且不会有任何报错，页面就是不动）。

 ## 用法

 ```swift
 OrientationLock.allowAll()   // 进内置网页
 OrientationLock.portrait()   // 退出时恢复
 ```

 改完之后系统会在下一次评估时（通常立刻）按新 mask 旋转界面；
 如果设备已经横着，从内置网页返回主页会自动转回竖屏。
 */
enum OrientationLock {

    private(set) static var mask: UIInterfaceOrientationMask = .portrait

    /// 主页：只允许竖屏。
    static func portrait() {
        mask = .portrait
    }

    /// 内置网页：横竖屏都允许（不含 iPad 的倒置）。
    ///
    /// 用 `.allButUpsideDown` 而不是 `.all`：iPhone 倒过来拿着用是极少见
    /// 场景，而它会让刘海跑到下方，页面顶部的返回气泡跟着跳，反而干扰。
    static func allowAll() {
        mask = .allButUpsideDown
    }

    /// 主动请求系统重新评估方向。
    ///
    /// 只改 `mask` 在多数情况下够用，但「从内置网页（可能正横着）返回主页」
    /// 时，系统未必立刻重算 —— 用户会看到主页停留在横屏、布局被挤扁。
    /// 这里显式通知一次。
    ///
    /// ## 两个 API 的分工
    ///
    /// - `setNeedsUpdateOfSupportedInterfaceOrientations()`（iOS 16+）：
    ///   让 VC 重新查询 `supportedInterfaceOrientations`，是官方推荐做法。
    /// - `requestGeometryUpdate`：**只在需要「主动转过去」时**才用。它有副作用
    ///   —— 会在用户没有转动设备时强制旋转界面，观感很怪。所以这里不用它，
    ///   只做「重新评估」。
    static func apply() {
        if #available(iOS 16.0, *) {
            for case let scene as UIWindowScene in UIApplication.shared.connectedScenes {
                for window in scene.windows {
                    window.rootViewController?
                        .setNeedsUpdateOfSupportedInterfaceOrientations()
                }
            }
            return
        }
        // iOS 15：没有 setNeedsUpdate…，只能靠「强设设备方向」+ 让系统重算。
        //
        // ⚠️ 这里必须判断 mask：强设 portrait 是**不可逆的**（会把界面真的
        // 转过去），只有在「锁定竖屏」时才该这么做。之前无条件设了 portrait，
        // 结果 iOS 15 上进内置网页也会被强行转回竖屏 —— 横屏支持等于没做。
        if mask == .portrait || mask == .portraitUpsideDown {
            UIDevice.current.setValue(
                UIInterfaceOrientation.portrait.rawValue, forKey: "orientation")
        }
        UIViewController.attemptRotationToDeviceOrientation()
    }
}

/**
 只做一件事的 AppDelegate：回答「现在允许哪些方向」。

 SwiftUI 的 `App` 生命周期没有方向回调，必须通过这个入口接进来。
 */
final class StarRadarAppDelegate: NSObject, UIApplicationDelegate {

    func application(
        _ application: UIApplication,
        supportedInterfaceOrientationsFor window: UIWindow?
    ) -> UIInterfaceOrientationMask {
        OrientationLock.mask
    }
}
