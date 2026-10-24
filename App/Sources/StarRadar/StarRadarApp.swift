import SwiftUI
import UIKit
import StarRadarCore

@main
struct StarRadarApp: App {

    // SwiftUI 的 App 生命周期没有「允许哪些方向」的回调，只能通过
    // AppDelegate 接进来。这个 delegate 只做这一件事。
    @UIApplicationDelegateAdaptor(StarRadarAppDelegate.self)
    private var appDelegate

    @StateObject private var service = RadarService()

    var body: some Scene {
        WindowGroup {
            HomeView(service: service)
                .preferredColorScheme(.light)   // 白底橙是设计基线，强制浅色
                .onAppear {
                    // 主页锁竖屏。放在这里而不是 init：从内置网页返回时
                    // 这个 onAppear 会再跑一次，正好把方向收回来。
                    OrientationLock.portrait()
                    OrientationLock.apply()
                }
                .onDisappear {
                    // 退出界面不该把代理带走：用户划掉界面 ≠ 想停代理。
                    // 真正的停止只在「停止代理」按钮里发生。
                }
        }
    }
}
