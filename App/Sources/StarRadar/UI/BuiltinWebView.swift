import SwiftUI
import WebKit
import StarRadarCore

/**
 内置网页 —— 全屏 WKWebView + 左上角返回气泡。

 ## 为什么单独做成一个全屏页面

 节点给的是「配好密钥的战术雷达页面」，用户打开后是长时间浏览，不是填个表
 就关的弹窗。全屏 + 沉浸能多给出 60pt 的垂直空间，而返回入口用一个悬浮气泡
 放在左上角，既明显又不挡内容。

 ## 横竖屏

 主页是竖屏卡片布局，内置网页是表格/地图类页面 —— **横屏才有意义**。
 所以进入本页时把方向解锁（`OrientationLock.allowAll()`），退出时锁回竖屏。

 两处细节值得记下来：

 1. **`Info.plist` 必须声明 landscape**，否则 delegate 返回的 mask 会被交集
    限制回竖屏，页面转不过来且没有任何报错。见 `Info.plist` 里的注释。
 2. **横屏时不能 `ignoresSafeArea`**：iPhone 横过来时刘海在左右两侧，
    全屏会让页面内容钻到刘海下面被遮住（战术雷达的侧栏正好在那里）。
    这里按宽高比判断：竖屏保持全屏沉浸，横屏把左右让给安全区。
 */
struct BuiltinWebScreen: View {

    let url: URL
    @Environment(\.dismiss) private var dismiss

    @State private var progress: Double = 0
    @State private var failure: String?

    var body: some View {
        GeometryReader { geometry in
            // 宽大于高即横屏。用尺寸判断而不是 sizeClass：iPhone 横屏时
            // compact/regular 的组合依机型而变，判断不可靠。
            let isLandscape = geometry.size.width > geometry.size.height

            ZStack(alignment: .topLeading) {
                Sr.bg.ignoresSafeArea()

                WebViewContainer(url: url, progress: $progress, failure: $failure)
                    // 竖屏：全屏沉浸（状态栏已隐藏，顶到屏幕边）
                    // 横屏：左右避让刘海，否则侧边内容被遮
                    .ignoresSafeArea(edges: isLandscape ? .bottom : .all)

                progressBar(isLandscape: isLandscape)

                backBubble(isLandscape: isLandscape)

                if let failure {
                    errorOverlay(failure)
                }
            }
        }
        .statusBar(hidden: true)
        .background(Sr.bg)
        .onAppear {
            // 进页面就解锁方向：用户此刻横过来是「想看宽一点」，
            // 不该被主页的竖屏锁拦住。
            OrientationLock.allowAll()
            OrientationLock.apply()
        }
        .onDisappear {
            // 退出立刻锁回竖屏。apply() 会请求系统重算，否则主页会
            // 停留在横屏、卡片被挤成两栏，观感很差。
            OrientationLock.portrait()
            OrientationLock.apply()
        }
    }

    /// 顶部细进度条（加载中是唯一需要看到的状态）。
    private func progressBar(isLandscape: Bool) -> some View {
        VStack(spacing: 0) {
            if progress > 0 && progress < 1 {
                GeometryReader { geo in
                    Rectangle()
                        .fill(Sr.accent)
                        .frame(width: geo.size.width * progress, height: 2)
                }
                .frame(height: 2)
            }
            Spacer()
        }
        // 横屏时顶部没有状态栏，进度条贴边即可；竖屏时也让它在安全区内，
        // 避免被圆角切掉。
        .ignoresSafeArea(edges: isLandscape ? .horizontal : .top)
    }

    /// 左上角返回气泡。
    ///
    /// 位置跟安全区走（ZStack 内的视图默认在安全区内），所以横屏时会自动
    /// 避开刘海 —— 不需要自己算左边距。
    private func backBubble(isLandscape: Bool) -> some View {
        Button {
            dismiss()
        } label: {
            Image(systemName: "chevron.left")
                .font(.system(size: 17, weight: .semibold))
                .foregroundColor(.white)
                .frame(width: 44, height: 44)
                .background(Sr.accent)
                .clipShape(Circle())
                .shadow(color: Color.black.opacity(0.18), radius: 8, x: 0, y: 3)
        }
        .padding(.leading, 12)
        // 横屏时垂直空间更紧，上边距收一点，给内容多点地方
        .padding(.top, isLandscape ? 8 : 14)
    }

    private func errorOverlay(_ message: String) -> some View {
        VStack(spacing: 10) {
            Image(systemName: "wifi.exclamationmark")
                .font(.system(size: 28))
                .foregroundColor(Sr.warn)
            Text("页面打不开")
                .font(.system(size: 15, weight: .semibold))
                .foregroundColor(Sr.fg)
            Text(message)
                .font(.system(size: 12))
                .foregroundColor(Sr.dim)
                .multilineTextAlignment(.center)
            Text("检查：本机开着代理、上报已连上、另一台设备也能打开这个地址")
                .font(.system(size: 11))
                .foregroundColor(Sr.line2)
                .multilineTextAlignment(.center)
        }
        .padding(20)
        .frame(maxWidth: 340)
        .background(Sr.surface)
        .cornerRadius(14)
        .shadow(color: Color.black.opacity(0.12), radius: 16, x: 0, y: 6)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.black.opacity(0.06))
    }
}

/// WKWebView 的 SwiftUI 包装。
private struct WebViewContainer: UIViewRepresentable {

    let url: URL
    @Binding var progress: Double
    @Binding var failure: String?

    func makeCoordinator() -> Coordinator {
        Coordinator(self)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.allowsInlineMediaPlayback = true
        configuration.userContentController.addUserScript(
            WKUserScript(source: WebViewContainer.viewportFixScript,
                         injectionTime: .atDocumentEnd,
                         forMainFrameOnly: true))

        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        webView.scrollView.contentInsetAdjustmentBehavior = .never
        webView.isOpaque = false
        webView.backgroundColor = UIColor.white

        // 进度用 KVO 读（estimatedProgress 每秒会变好几次，
        // 用 delegate 拿不到中间值）
        context.coordinator.observe(webView)
        webView.load(URLRequest(url: url))
        return webView
    }

    /// 旋转时不需要重建 WebView，SwiftUI 会把新 frame 传下来，
    /// WKWebView 自己会 reflow。
    func updateUIView(_ webView: WKWebView, context: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        coordinator.stopObserving()
        webView.stopLoading()
    }

    /**
     给「没有 viewport meta」的页面补一条。

     节点上的页面是别人写的，未必声明了 viewport。没有它时 WKWebView 会按
     桌面宽度（980px）渲染再缩小，**横屏时会糊成一团小字**。

     关键在 `if (!已有 viewport)` 这个判断：页面自己声明了就完全不动它 ——
     覆盖掉一个精心调过的 viewport 反而会把原本正常的页面弄坏。
     */
    private static let viewportFixScript = """
    (function () {
      try {
        if (document.querySelector('meta[name="viewport"]')) { return; }
        var meta = document.createElement('meta');
        meta.name = 'viewport';
        meta.content = 'width=device-width, initial-scale=1.0, viewport-fit=cover';
        (document.head || document.documentElement).appendChild(meta);
      } catch (e) {}
    })();
    """

    final class Coordinator: NSObject, WKNavigationDelegate {
        private let parent: WebViewContainer
        private var observation: NSKeyValueObservation?

        init(_ parent: WebViewContainer) {
            self.parent = parent
        }

        func observe(_ webView: WKWebView) {
            observation = webView.observe(\.estimatedProgress,
                                          options: [.new]) { [weak self] webView, _ in
                DispatchQueue.main.async {
                    self?.parent.progress = webView.estimatedProgress
                }
            }
        }

        func stopObserving() {
            observation?.invalidate()
            observation = nil
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            DispatchQueue.main.async { self.parent.progress = 1 }
        }

        func webView(_ webView: WKWebView,
                     didFailProvisionalNavigation navigation: WKNavigation!,
                     withError error: Error) {
            DispatchQueue.main.async {
                self.parent.failure = Self.describe(error)
            }
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!,
                     withError error: Error) {
            DispatchQueue.main.async {
                self.parent.failure = Self.describe(error)
            }
        }

        private static func describe(_ error: Error) -> String {
            let nsError = error as NSError
            switch nsError.code {
            case NSURLErrorCannotConnectToHost:
                return "连不上这个地址：节点上的分享页服务没起来，或端口被拦"
            case NSURLErrorTimedOut:
                return "加载超时：网络不通"
            case NSURLErrorNotConnectedToInternet:
                return "本机没有网络"
            case NSURLErrorAppTransportSecurityRequiresSecureConnection:
                return "系统拦了明文 HTTP（ATS 配置缺失）"
            default:
                return nsError.localizedDescription
            }
        }
    }
}
