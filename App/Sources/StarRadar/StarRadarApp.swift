import SwiftUI
import UIKit
import StarRadarCore

@main
struct StarRadarApp: App {

    @StateObject private var service = RadarService()

    var body: some Scene {
        WindowGroup {
            HomeView(service: service)
                .preferredColorScheme(.light)   // 白底橙是设计基线，强制浅色
                .onDisappear {
                    // 退出界面不该把代理带走：用户划掉界面 ≠ 想停代理。
                    // 真正的停止只在「停止代理」按钮里发生。
                }
        }
    }
}
