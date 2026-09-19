// iOS (Swift): WKWebView with camera access (iOS 14.3+), or SFSafariViewController.
// Info.plist: NSCameraUsageDescription = "We use the camera to confirm it is you."
import SafariServices
import UIKit
import WebKit

let redirectURL = "https://yourapp.example/biometrics/done" // the session's appearance.redirectUrl

final class FaceCaptureViewController: UIViewController, WKNavigationDelegate, WKUIDelegate {
    var captureURL: URL!
    var onFinish: (() -> Void)?

    override func viewDidLoad() {
        super.viewDidLoad()
        let config = WKWebViewConfiguration()
        config.allowsInlineMediaPlayback = true // camera video inside the page
        config.mediaTypesRequiringUserActionForPlayback = []
        let webView = WKWebView(frame: view.bounds, configuration: config)
        webView.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        webView.navigationDelegate = self
        webView.uiDelegate = self
        view.addSubview(webView)
        webView.load(URLRequest(url: captureURL))
    }

    // iOS 15+: grants the camera only to the capture origin (the system prompt uses NSCameraUsageDescription).
    @available(iOS 15.0, *)
    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin,
                 initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType,
                 decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        decisionHandler(origin.host == captureURL.host && type == .camera ? .grant : .deny)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = navigationAction.request.url?.absoluteString, url.hasPrefix(redirectURL) {
            decisionHandler(.cancel)
            onFinish?() // finished; the result comes in your server's webhook
            dismiss(animated: true)
            return
        }
        decisionHandler(.allow)
    }
}

// Alternative: SFSafariViewController (Safari handles the camera and the permission).
func openInSafari(_ presenter: UIViewController, captureURL: URL) {
    presenter.present(SFSafariViewController(url: captureURL), animated: true)
}
