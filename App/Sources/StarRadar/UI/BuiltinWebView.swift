import SwiftUI
import WebKit

/**
 内置网页 —— 全屏 WKWebView + 左上角返回气泡。

 ## 为什么单独做成一个全屏页面

 节点给的是「配好密钥的战术雷达页面」，用户打开后是长时间浏览，
 不是填个表就关的弹窗。全屏 + 沉浸能多给出 60pt 的垂直空间，
 而返回入口用一个悬浮气泡放在左上角，既明显又不挡内容。
 */
struct BuiltinWebScreen: View {

    let url: URL
    @Environment(\.dismiss) private var dismiss

    @State private var progress: Double = 0
    @State private var failure: String?

    var body: some View {
        ZStack(alignment: .topLeading) {
            WebViewContainer(url: url, progress: $progress, failure: $failure)
                .ignoresSafeArea()

            // 顶部细进度条（加载中是唯一需要看到的状态）
            VStack(spacing: 0) {
                if progress > 0 && progress < 1 {
                    GeometryReader { geometry in
                        Rectangle()
                            .fill(Sr.accent)
                            .frame(width: geometry.size.width * progress, height: 2)
                    }
                    .frame(height: 2)
                }
                Spacer()
            }
            .ignoresSafeArea(edges: .top)

            backBubble

            if let failure {
                errorOverlay(failure)
            }
        }
        .statusBar(hidden: true)
        .background(Sr.bg)
    }

    private var backBubble: some View {
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
        .padding(.leading, 14)
        .padding(.top, 14)
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
        .frame(maxWidth: 300)
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

    func updateUIView(_ webView: WKWebView, context: Context) {}

    static func dismantleUIView(_ webView: WKWebView, coordinator: Coordinator) {
        coordinator.stopObserving()
        webView.stopLoading()
    }

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
