// Flutter: capture in a WebView. pubspec: webview_flutter, webview_flutter_android, permission_handler.
// iOS: NSCameraUsageDescription. Android: <uses-permission android:name="android.permission.CAMERA"/>.
// The end of the flow is the navigation to appearance.redirectUrl (set when YOUR server creates the session).
import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:webview_flutter_android/webview_flutter_android.dart';

const redirectUrl = 'https://yourapp.example/biometrics/done';

class FaceCapture extends StatefulWidget {
  const FaceCapture({super.key, required this.captureUrl, required this.onFinish});
  final String captureUrl;
  final VoidCallback onFinish;

  @override
  State<FaceCapture> createState() => _FaceCaptureState();
}

class _FaceCaptureState extends State<FaceCapture> {
  WebViewController? _controller;

  @override
  void initState() {
    super.initState();
    _open();
  }

  Future<void> _open() async {
    if (!await Permission.camera.request().isGranted) return;
    final controller = WebViewController.fromPlatformCreationParams(
      const PlatformWebViewControllerCreationParams(),
      onPermissionRequest: (request) => request.grant(), // forwards the camera to the page
    )
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(NavigationDelegate(
        onNavigationRequest: (request) {
          if (request.url.startsWith(redirectUrl)) {
            widget.onFinish(); // finished; the result comes in your server's webhook
            return NavigationDecision.prevent;
          }
          return NavigationDecision.navigate;
        },
      ));
    if (controller.platform is AndroidWebViewController) {
      (controller.platform as AndroidWebViewController).setMediaPlaybackRequiresUserGesture(false);
    }
    await controller.loadRequest(Uri.parse(widget.captureUrl));
    setState(() => _controller = controller);
  }

  @override
  Widget build(BuildContext context) =>
      _controller == null ? const Center(child: CircularProgressIndicator()) : WebViewWidget(controller: _controller!);
}
